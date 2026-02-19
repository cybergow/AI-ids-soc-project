"""
GNN-based flow anomaly detection.

This module trains a GCN on flow features using a k-NN graph and provides
an inference helper for streaming flow scoring.
"""

from __future__ import annotations

import json
import os
from collections import deque
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

import torch
import torch.nn.functional as F

try:
    from torch_geometric.data import Data
    from torch_geometric.nn import GCNConv
    from torch_geometric.utils import add_self_loops
    TORCH_GEOMETRIC_AVAILABLE = True
except Exception:
    TORCH_GEOMETRIC_AVAILABLE = False

FEATURE_COLUMNS = [
    "duration",
    "pkt_count",
    "byte_count",
    "src2dst_pkts",
    "dst2src_pkts",
    "mean_pkt_size",
]

COLUMN_ALIASES = {
    "pktcount": "pkt_count",
    "bytecount": "byte_count",
    "src2dstpkts": "src2dst_pkts",
    "dst2srcpkts": "dst2src_pkts",
    "meanpktsize": "mean_pkt_size",
}

DEFAULT_CONFIG = {
    "features": FEATURE_COLUMNS,
    "k_neighbors": 8,
    "threshold": 0.95,
    "min_nodes": 5,
    "window_size": 120,
    "hidden_dim": 32,
    "dropout": 0.2,
}


def _standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns=COLUMN_ALIASES)
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    return df


def load_flow_dataset(
    benign_file: str,
    attack_file: str,
    features: Optional[List[str]] = None,
) -> Tuple[np.ndarray, np.ndarray]:
    features = features or FEATURE_COLUMNS

    benign_df = pd.read_csv(benign_file)
    benign_df = _standardize_columns(benign_df)
    benign_df["label"] = 0

    attack_df = pd.read_csv(attack_file)
    attack_df = _standardize_columns(attack_df)
    attack_df["label"] = 1

    data = pd.concat([benign_df, attack_df], ignore_index=True)
    X = data[features].astype(float).to_numpy()
    y = data["label"].astype(int).to_numpy()
    return X, y


def build_knn_edge_index(x: np.ndarray, k_neighbors: int) -> torch.Tensor:
    if len(x) <= 1:
        return torch.empty((2, 0), dtype=torch.long)

    n_neighbors = min(k_neighbors + 1, len(x))
    nn = NearestNeighbors(n_neighbors=n_neighbors, metric="euclidean")
    nn.fit(x)
    _, indices = nn.kneighbors(x)

    edges: List[Tuple[int, int]] = []
    for i, neighbors in enumerate(indices):
        for j in neighbors[1:]:
            edges.append((i, int(j)))
            edges.append((int(j), i))

    if not edges:
        return torch.empty((2, 0), dtype=torch.long)

    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    return edge_index


def build_graph_data(x: np.ndarray, k_neighbors: int) -> Data:
    edge_index = build_knn_edge_index(x, k_neighbors)
    edge_index, _ = add_self_loops(edge_index, num_nodes=len(x))
    return Data(x=torch.tensor(x, dtype=torch.float32), edge_index=edge_index)


class FlowGCN(torch.nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 32, dropout: float = 0.2):
        super().__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, 1)
        self.dropout = dropout

    def forward(self, data: Data) -> torch.Tensor:
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv2(x, edge_index)
        return x.view(-1)


def train_gnn_model(
    benign_file: str = "training_data/benign_flows.csv",
    attack_file: str = "training_data/attack_flows.csv",
    model_path: str = "gnn_flow_model.pt",
    scaler_path: str = "gnn_flow_scaler.pkl",
    config_path: str = "gnn_flow_config.json",
    epochs: int = 40,
    learning_rate: float = 1e-3,
    k_neighbors: int = DEFAULT_CONFIG["k_neighbors"],
    hidden_dim: int = DEFAULT_CONFIG["hidden_dim"],
    dropout: float = DEFAULT_CONFIG["dropout"],
) -> Dict[str, float]:
    if not TORCH_GEOMETRIC_AVAILABLE:
        raise RuntimeError("torch_geometric is not available. Install torch-geometric first.")

    X, y = load_flow_dataset(benign_file, attack_file)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    data = build_graph_data(X_scaled, k_neighbors)
    data.y = torch.tensor(y, dtype=torch.float32)

    train_idx, test_idx = train_test_split(
        np.arange(len(y)), test_size=0.2, stratify=y, random_state=42
    )
    train_mask = torch.zeros(len(y), dtype=torch.bool)
    test_mask = torch.zeros(len(y), dtype=torch.bool)
    train_mask[train_idx] = True
    test_mask[test_idx] = True
    data.train_mask = train_mask
    data.test_mask = test_mask

    model = FlowGCN(input_dim=X_scaled.shape[1], hidden_dim=hidden_dim, dropout=dropout)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=1e-4)

    for _ in range(epochs):
        model.train()
        optimizer.zero_grad()
        logits = model(data)
        loss = F.binary_cross_entropy_with_logits(logits[data.train_mask], data.y[data.train_mask])
        loss.backward()
        optimizer.step()

    model.eval()
    with torch.no_grad():
        logits = model(data)
        probs = torch.sigmoid(logits)
        preds = (probs >= 0.5).long()
        y_true = data.y.long()
        correct = (preds[data.test_mask] == y_true[data.test_mask]).sum().item()
        total = int(data.test_mask.sum().item())
        accuracy = float(correct / max(1, total))

    torch.save(model.state_dict(), model_path)
    joblib.dump(scaler, scaler_path)

    config = {
        **DEFAULT_CONFIG,
        "k_neighbors": k_neighbors,
        "hidden_dim": hidden_dim,
        "dropout": dropout,
        "features": FEATURE_COLUMNS,
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    return {"accuracy": accuracy}


class GNNFlowScorer:
    def __init__(
        self,
        model_path: str = "gnn_flow_model.pt",
        scaler_path: str = "gnn_flow_scaler.pkl",
        config_path: str = "gnn_flow_config.json",
    ):
        self.is_ready = False
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.config_path = config_path

        if not TORCH_GEOMETRIC_AVAILABLE:
            return
        if not (os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(config_path)):
            return

        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        self.features = config.get("features", FEATURE_COLUMNS)
        self.k_neighbors = int(config.get("k_neighbors", DEFAULT_CONFIG["k_neighbors"]))
        self.threshold = float(config.get("threshold", DEFAULT_CONFIG["threshold"]))
        self.min_nodes = int(config.get("min_nodes", DEFAULT_CONFIG["min_nodes"]))
        self.window_size = int(config.get("window_size", DEFAULT_CONFIG["window_size"]))
        hidden_dim = int(config.get("hidden_dim", DEFAULT_CONFIG["hidden_dim"]))
        dropout = float(config.get("dropout", DEFAULT_CONFIG["dropout"]))

        self.scaler = joblib.load(scaler_path)
        self.model = FlowGCN(input_dim=len(self.features), hidden_dim=hidden_dim, dropout=dropout)
        self.model.load_state_dict(torch.load(model_path, map_location="cpu"))
        self.model.eval()

        self.history: deque[list[float]] = deque(maxlen=self.window_size)
        self.is_ready = True

    def _vectorize(self, feat: Dict[str, float]) -> List[float]:
        values: List[float] = []
        for col in self.features:
            values.append(float(feat.get(col, 0.0)))
        return values

    def score_flow(self, feat: Dict[str, float]) -> Tuple[Optional[float], bool, Optional[str]]:
        if not self.is_ready:
            return None, False, None

        vec = self._vectorize(feat)
        if len(self.history) < self.min_nodes:
            self.history.append(vec)
            return None, False, None

        window = list(self.history) + [vec]
        x = np.array(window, dtype=float)
        x_scaled = self.scaler.transform(x)

        data = build_graph_data(x_scaled, self.k_neighbors)
        with torch.no_grad():
            logits = self.model(data)
            prob = torch.sigmoid(logits[-1]).item()

        is_attack = prob >= self.threshold
        reason = f"GNN score {prob:.2f}" if is_attack else ""

        self.history.append(vec)
        return float(prob), bool(is_attack), reason
