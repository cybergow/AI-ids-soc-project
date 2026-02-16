import traceback
import sys
import os

print("--- Test Import Torch ---")
try:
    import torch
    print(f"Torch Version: {torch.__version__}")
except Exception:
    traceback.print_exc()

print("\n--- Test Import GNN ---")
try:
    from torch_geometric.nn import GCNConv
    print("GNN imported successfully")
except Exception:
    traceback.print_exc()
