"""
AI Training Pipeline - FIXED VERSION
Isolation Forest for Real-Time Threat Detection
Complete implementation with dataset generation, training, and real-time detection
Author: AI-IDS SOC Team
Date: January 29, 2026
Status: Production Ready - FIXED
"""

import csv
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import json
import os
from datetime import datetime
import logging
import random
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# PART 1: ATTACK DATASET GENERATOR
# ============================================================================

class AttackDatasetGenerator:
    """Generate realistic benign and attack network flow datasets"""
    
    def __init__(self):
        self.feature_names = [
            'duration', 'pktcount', 'bytecount', 'src2dstpkts',
            'dst2srcpkts', 'meanpktsize', 'tcpsyn', 'tcprst',
            'process_memory', 'registry_mods', 'file_ops', 'dns_queries',
            'arp_packets', 'cpu_spike', 'disk_spike', 'network_spike'
        ]
        random.seed(42)
        np.random.seed(42)
    
    def generate_benign_flows(self, count=1000):
        """Generate normal, non-malicious network flows"""
        benign_flows = []
        
        for _ in range(count):
            flow = {
                'duration': random.uniform(60, 300),
                'pktcount': random.randint(100, 2000),
                'bytecount': random.randint(1000, 5000000),
                'src2dstpkts': random.randint(50, 1500),
                'dst2srcpkts': random.randint(40, 1000),
                'meanpktsize': random.uniform(50, 500),
                'tcpsyn': random.randint(1, 50),
                'tcprst': random.randint(0, 20),
                'process_memory': random.uniform(20, 80),
                'registry_mods': random.randint(0, 5),
                'file_ops': random.randint(5, 50),
                'dns_queries': random.randint(1, 10),
                'arp_packets': random.randint(0, 5),
                'cpu_spike': random.uniform(5, 30),
                'disk_spike': random.uniform(5, 20),
                'network_spike': random.uniform(10, 100),
                'label': 'benign'
            }
            benign_flows.append(flow)
        
        logger.info(f"  ✓ Generated {count} benign flows")
        return benign_flows
    
    def generate_fileless_malware_flows(self, count=150):
        """Generate fileless malware attack flows"""
        attack_flows = []
        
        for _ in range(count):
            flow = {
                'duration': random.uniform(5, 30),
                'pktcount': random.randint(500, 5000),
                'bytecount': random.randint(100000, 10000000),
                'src2dstpkts': random.randint(100, 2000),
                'dst2srcpkts': random.randint(50, 1000),
                'meanpktsize': random.uniform(100, 800),
                'tcpsyn': random.randint(20, 100),
                'tcprst': random.randint(10, 50),
                'process_memory': random.uniform(150, 400),
                'registry_mods': random.randint(5, 30),
                'file_ops': random.randint(10, 100),
                'dns_queries': random.randint(20, 150),
                'arp_packets': random.randint(2, 20),
                'cpu_spike': random.uniform(50, 95),
                'disk_spike': random.uniform(20, 60),
                'network_spike': random.uniform(50, 300),
                'label': 'fileless_malware'
            }
            attack_flows.append(flow)
        
        logger.info(f"  ✓ Generated {count} fileless malware flows")
        return attack_flows
    
    def generate_ransomware_flows(self, count=150):
        """Generate ransomware attack flows"""
        attack_flows = []
        
        for _ in range(count):
            flow = {
                'duration': random.uniform(10, 60),
                'pktcount': random.randint(5000, 100000),
                'bytecount': random.randint(500000000, 10000000000),
                'src2dstpkts': random.randint(2000, 50000),
                'dst2srcpkts': random.randint(1000, 30000),
                'meanpktsize': random.uniform(500, 1500),
                'tcpsyn': random.randint(50, 200),
                'tcprst': random.randint(30, 100),
                'process_memory': random.uniform(100, 300),
                'registry_mods': random.randint(0, 10),
                'file_ops': random.randint(500, 2000),
                'dns_queries': random.randint(5, 30),
                'arp_packets': random.randint(0, 5),
                'cpu_spike': random.uniform(60, 99),
                'disk_spike': random.uniform(85, 99),
                'network_spike': random.uniform(200, 800),
                'label': 'ransomware'
            }
            attack_flows.append(flow)
        
        logger.info(f"  ✓ Generated {count} ransomware flows")
        return attack_flows
    
    def generate_mitm_dns_flows(self, count=150):
        """Generate MITM/DNS exfiltration attack flows"""
        attack_flows = []
        
        for _ in range(count):
            flow = {
                'duration': random.uniform(30, 180),
                'pktcount': random.randint(1000, 10000),
                'bytecount': random.randint(100000, 50000000),
                'src2dstpkts': random.randint(300, 5000),
                'dst2srcpkts': random.randint(200, 3000),
                'meanpktsize': random.uniform(100, 600),
                'tcpsyn': random.randint(10, 60),
                'tcprst': random.randint(5, 30),
                'process_memory': random.uniform(80, 200),
                'registry_mods': random.randint(0, 5),
                'file_ops': random.randint(10, 100),
                'dns_queries': random.randint(100, 500),
                'arp_packets': random.randint(50, 300),
                'cpu_spike': random.uniform(30, 70),
                'disk_spike': random.uniform(10, 40),
                'network_spike': random.uniform(200, 600),
                'label': 'mitm_dns'
            }
            attack_flows.append(flow)
        
        logger.info(f"  ✓ Generated {count} MITM/DNS flows")
        return attack_flows
    
    def generate_payload_injection_flows(self, count=150):
        """Generate payload injection attack flows"""
        attack_flows = []
        
        for _ in range(count):
            flow = {
                'duration': random.uniform(5, 45),
                'pktcount': random.randint(500, 8000),
                'bytecount': random.randint(50000, 100000000),
                'src2dstpkts': random.randint(100, 3000),
                'dst2srcpkts': random.randint(50, 2000),
                'meanpktsize': random.uniform(80, 600),
                'tcpsyn': random.randint(30, 120),
                'tcprst': random.randint(20, 80),
                'process_memory': random.uniform(200, 500),
                'registry_mods': random.randint(5, 20),
                'file_ops': random.randint(50, 300),
                'dns_queries': random.randint(10, 80),
                'arp_packets': random.randint(0, 10),
                'cpu_spike': random.uniform(50, 90),
                'disk_spike': random.uniform(20, 60),
                'network_spike': random.uniform(100, 500),
                'label': 'payload_injection'
            }
            attack_flows.append(flow)
        
        logger.info(f"  ✓ Generated {count} payload injection flows")
        return attack_flows
    
    def save_to_csv(self, flows, filename):
        """Save flows to CSV file"""
        if not flows:
            logger.warning(f"No flows to save to {filename}")
            return
        
        os.makedirs('training_data', exist_ok=True)
        filepath = os.path.join('training_data', filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flows[0].keys())
            writer.writeheader()
            writer.writerows(flows)
        
        logger.info(f"  ✓ Saved {len(flows)} flows to {filepath}")

# ============================================================================
# PART 2: ISOLATION FOREST TRAINER
# ============================================================================

class IsolationForestTrainer:
    """Train and manage Isolation Forest model"""
    
    def __init__(self):
        self.feature_names = [
            'duration', 'pktcount', 'bytecount', 'src2dstpkts',
            'dst2srcpkts', 'meanpktsize', 'tcpsyn', 'tcprst',
            'process_memory', 'registry_mods', 'file_ops', 'dns_queries',
            'arp_packets', 'cpu_spike', 'disk_spike', 'network_spike'
        ]
        self.model = None
        self.scaler = None
    
    def load_training_data(self, benign_file, attack_file):
        """Load training data from CSV files"""
        logger.info(f"  [Step 2.1] Loading training data...")
        
        benign_df = pd.read_csv(benign_file)
        attack_df = pd.read_csv(attack_file)
        
        combined_df = pd.concat([benign_df, attack_df], ignore_index=True)
        combined_df = combined_df.sample(frac=1).reset_index(drop=True)
        
        logger.info(f"  ✓ Loaded {len(benign_df)} benign flows")
        logger.info(f"  ✓ Loaded {len(attack_df)} attack flows")
        logger.info(f"  ✓ Total: {len(combined_df)} samples")
        
        return combined_df
    
    def extract_features(self, df):
        """Extract features and prepare for training"""
        logger.info(f"  [Step 2.2] Preparing features...")
        
        X = df[self.feature_names].values
        logger.info(f"  ✓ Extracted {X.shape[1]} features from {X.shape[0]} samples")
        
        return X
    
    def train(self, X, contamination=0.2, n_estimators=100):
        """Train Isolation Forest model"""
        logger.info(f"  [Step 2.3] Training Isolation Forest model...")
        logger.info(f"    - Samples: {X.shape[0]}")
        logger.info(f"    - Features: {X.shape[1]}")
        logger.info(f"    - Contamination: {contamination*100:.1f}%")
        logger.info(f"    - Trees: {n_estimators}")
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        logger.info(f"  ✓ Features scaled")
        
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)
        logger.info(f"  ✓ Model training complete!")
        
        return X_scaled
    
    def evaluate(self, X_scaled, df):
        """Evaluate model performance"""
        logger.info(f"  [Step 2.5] Evaluating model...")
        
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        y_true = (df['label'] != 'benign').astype(int).values
        y_pred = (predictions == -1).astype(int)
        
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred)
        
        logger.info(f"  ✓ Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        logger.info(f"  ✓ Precision: {precision:.4f}")
        logger.info(f"  ✓ Recall:    {recall:.4f}")
        logger.info(f"  ✓ F1-Score:  {f1:.4f}")
        logger.info(f"  ✓ Confusion Matrix:")
        logger.info(f"      True Negatives:  {cm[0,0]}")
        logger.info(f"      False Positives: {cm[0,1]}")
        logger.info(f"      False Negatives: {cm[1,0]}")
        logger.info(f"      True Positives:  {cm[1,1]}")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm.tolist()
        }
    
    def save_model(self, model_path='backend/isoforest_model.pkl', 
                   scaler_path='backend/isoforest_scaler.pkl'):
        """Save trained model and scaler"""
        logger.info(f"  [Step 2.4] Saving models...")
        
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        
        logger.info(f"  ✓ Model saved to {model_path}")
        logger.info(f"  ✓ Scaler saved to {scaler_path}")
        
        model_size = os.path.getsize(model_path) / (1024 * 1024)
        scaler_size = os.path.getsize(scaler_path) / 1024
        
        logger.info(f"  ✓ Model size: {model_size:.1f} MB")
        logger.info(f"  ✓ Scaler size: {scaler_size:.1f} KB")

# ============================================================================
# PART 3: REAL-TIME ATTACK DETECTOR
# ============================================================================

class RealtimeAttackDetector:
    """Use trained model for real-time threat detection"""
    
    def __init__(self, model_path, scaler_path):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_names = [
            'duration', 'pktcount', 'bytecount', 'src2dstpkts',
            'dst2srcpkts', 'meanpktsize', 'tcpsyn', 'tcprst',
            'process_memory', 'registry_mods', 'file_ops', 'dns_queries',
            'arp_packets', 'cpu_spike', 'disk_spike', 'network_spike'
        ]
    
    def detect_anomaly(self, flow_dict):
        """Detect if a flow is anomalous (attack)"""
        try:
            features = [flow_dict[name] for name in self.feature_names]
            features = np.array(features).reshape(1, -1)
            
            features_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict(features_scaled)[0]
            anomaly_score = abs(self.model.score_samples(features_scaled)[0])
            
            if anomaly_score < 0.2:
                risk_level = "LOW"
            elif anomaly_score < 0.4:
                risk_level = "MEDIUM"
            elif anomaly_score < 0.6:
                risk_level = "HIGH"
            else:
                risk_level = "CRITICAL"
            
            return {
                'is_anomaly': prediction == -1,
                'anomaly_score': anomaly_score,
                'risk_level': risk_level,
                'confidence': anomaly_score
            }
        except Exception as e:
            logger.error(f"Detection error: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'risk_level': 'UNKNOWN',
                'confidence': 0.0
            }

# ============================================================================
# PART 4: MAIN TRAINING PIPELINE
# ============================================================================

def run_training_pipeline():
    """Complete end-to-end training pipeline"""
    
    logger.info("=" * 80)
    logger.info("AI THREAT DETECTION TRAINING PIPELINE")
    logger.info("Isolation Forest Model")
    logger.info("=" * 80)
    
    logger.info("\n[★] STEP 1: GENERATING TRAINING DATASET")
    logger.info("=" * 80)
    
    generator = AttackDatasetGenerator()
    
    benign = generator.generate_benign_flows(1000)
    fileless = generator.generate_fileless_malware_flows(150)
    ransomware = generator.generate_ransomware_flows(150)
    mitm_dns = generator.generate_mitm_dns_flows(150)
    payload = generator.generate_payload_injection_flows(150)
    
    generator.save_to_csv(benign, 'benign_flows.csv')
    
    attack_flows = fileless + ransomware + mitm_dns + payload
    generator.save_to_csv(attack_flows, 'attack_flows.csv')
    
    logger.info(f"\n  ✓ Total flows generated: {len(benign) + len(attack_flows)}")
    logger.info(f"    - Benign: {len(benign)}")
    logger.info(f"    - Attacks: {len(attack_flows)}")
    
    logger.info("\n[★] STEP 2: TRAINING MODEL")
    logger.info("=" * 80)
    
    trainer = IsolationForestTrainer()
    
    df = trainer.load_training_data(
        'training_data/benign_flows.csv',
        'training_data/attack_flows.csv'
    )
    
    X = trainer.extract_features(df)
    X_scaled = trainer.train(X, contamination=0.2, n_estimators=100)
    
    metrics = trainer.evaluate(X_scaled, df)
    trainer.save_model()
    
    logger.info("\n[★] STEP 3 & 4: TESTING ON SIMULATED ATTACKS")
    logger.info("=" * 80)
    
    detector = RealtimeAttackDetector(
        'backend/isoforest_model.pkl',
        'backend/isoforest_scaler.pkl'
    )
    
    test_cases = [
        {
            'name': 'Fileless Malware Attack',
            'flow': {
                'duration': 10, 'pktcount': 5000, 'bytecount': 10000000,
                'src2dstpkts': 2000, 'dst2srcpkts': 500, 'meanpktsize': 600,
                'tcpsyn': 80, 'tcprst': 40, 'process_memory': 280,
                'registry_mods': 20, 'file_ops': 50, 'dns_queries': 100,
                'arp_packets': 5, 'cpu_spike': 85, 'disk_spike': 40,
                'network_spike': 300
            }
        },
        {
            'name': 'Ransomware Attack',
            'flow': {
                'duration': 30, 'pktcount': 50000, 'bytecount': 5000000000,
                'src2dstpkts': 25000, 'dst2srcpkts': 20000, 'meanpktsize': 1000,
                'tcpsyn': 150, 'tcprst': 80, 'process_memory': 200,
                'registry_mods': 5, 'file_ops': 1500, 'dns_queries': 20,
                'arp_packets': 2, 'cpu_spike': 95, 'disk_spike': 98,
                'network_spike': 700
            }
        },
        {
            'name': 'MITM/DNS Attack',
            'flow': {
                'duration': 60, 'pktcount': 5000, 'bytecount': 30000000,
                'src2dstpkts': 3000, 'dst2srcpkts': 1500, 'meanpktsize': 400,
                'tcpsyn': 40, 'tcprst': 20, 'process_memory': 120,
                'registry_mods': 3, 'file_ops': 30, 'dns_queries': 300,
                'arp_packets': 200, 'cpu_spike': 50, 'disk_spike': 30,
                'network_spike': 500
            }
        },
        {
            'name': 'Normal Traffic (Benign)',
            'flow': {
                'duration': 120, 'pktcount': 800, 'bytecount': 2000000,
                'src2dstpkts': 600, 'dst2srcpkts': 150, 'meanpktsize': 200,
                'tcpsyn': 20, 'tcprst': 5, 'process_memory': 60,
                'registry_mods': 2, 'file_ops': 20, 'dns_queries': 5,
                'arp_packets': 2, 'cpu_spike': 20, 'disk_spike': 15,
                'network_spike': 50
            }
        }
    ]
    
    for test in test_cases:
        result = detector.detect_anomaly(test['flow'])
        
        if result['is_anomaly']:
            status = f"🚨 ATTACK DETECTED - {test['name']}"
        else:
            status = f"✓ BENIGN - {test['name']}"
        
        logger.info(f"  {status}")
        logger.info(f"    Anomaly Score: {result['anomaly_score']:.4f}")
        logger.info(f"    Risk Level: {result['risk_level']}")
    
    logger.info("\n" + "=" * 80)
    logger.info("✅ TRAINING COMPLETE!")
    logger.info("=" * 80)
    logger.info(f"\nMetrics:")
    logger.info(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
    logger.info(f"  Precision: {metrics['precision']*100:.2f}%")
    logger.info(f"  Recall:    {metrics['recall']*100:.2f}%")
    logger.info(f"  F1-Score:  {metrics['f1_score']:.4f}")
    logger.info(f"\nModels saved:")
    logger.info(f"  ✓ backend/isoforest_model.pkl")
    logger.info(f"  ✓ backend/isoforest_scaler.pkl")
    logger.info(f"\nReady for: Real-time threat detection!")
    logger.info("=" * 80)

if __name__ == '__main__':
    run_training_pipeline()