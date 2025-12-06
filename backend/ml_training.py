#!/usr/bin/env python3
# ml_training_simple.py - No pandas, uses only numpy + sklearn

import csv
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib
import json
from datetime import datetime

class IsolationForestTrainer:
    """Train Isolation Forest model - No pandas required"""
    
    def __init__(self):
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self.feature_cols = ['duration', 'pkt_count', 'byte_count', 
                            'src2dst_pkts', 'dst2src_pkts', 'mean_pkt_size',
                            'tcp_syn', 'tcp_rst']
    
    def load_training_data_from_csv(self, normal_file='training_data/normal_flows.csv'):
        """Load training data from CSV without pandas"""
        print(f"📥 Loading data from {normal_file}...")
        
        X = []
        with open(normal_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                features = [float(row[col]) for col in self.feature_cols]
                X.append(features)
        
        X = np.array(X)
        print(f"   Loaded {len(X)} samples")
        return X
    
    def fit_scaler(self, X):
        """Fit StandardScaler"""
        print("📊 Fitting scaler...")
        self.scaler = StandardScaler()
        self.scaler.fit(X)
        print(f"✅ Scaler fitted")
        scaler = self.scaler
        if scaler is not None:
            mean_vals = getattr(scaler, 'mean_', None)
            scale_vals = getattr(scaler, 'scale_', None)
            if mean_vals is not None and scale_vals is not None:
                print(f"   Feature means (first 3): {mean_vals[:3]}")
                print(f"   Feature stds (first 3):  {scale_vals[:3]}")
        return self.scaler
    
    def train_model(self, X, contamination=0.1, n_estimators=100):
        """Train Isolation Forest"""
        print("\n🧠 Training Isolation Forest...")
        print(f"   Samples: {len(X)}")
        print(f"   Features: {len(self.feature_cols)}")
        print(f"   Contamination: {contamination*100}%")
        print(f"   Trees: {n_estimators}")
        
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X)
        print("✅ Model trained successfully!")
        return self.model
    
    def save_models(self, model_path='isoforest_model.pkl', 
                   scaler_path='isoforest_scaler.pkl'):
        """Save trained model and scaler"""
        print(f"\n💾 Saving models...")
        
        if self.model is None:
            print("❌ Model not trained yet")
            return
        
        joblib.dump(self.model, model_path)
        print(f"✅ Model saved to {model_path}")
        
        joblib.dump(self.scaler, scaler_path)
        print(f"✅ Scaler saved to {scaler_path}")
        
        metadata = {
            'trained_at': datetime.now().isoformat(),
            'features': self.feature_cols,
            'n_features': len(self.feature_cols),
            'n_estimators': getattr(self.model, 'n_estimators', 100),
            'contamination': getattr(self.model, 'contamination', 0.1),
            'model_type': 'IsolationForest',
        }
        
        with open('model_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"✅ Metadata saved to model_metadata.json")
    
    def full_training_pipeline(self, normal_file='training_data/normal_flows.csv'):
        """Complete training pipeline"""
        print("="*60)
        print("🚀 STARTING ML TRAINING PIPELINE")
        print("="*60 + "\n")
        
        # Load data
        X = self.load_training_data_from_csv(normal_file)
        
        # Fit scaler
        self.fit_scaler(X)
        
        # Scale data
        if self.scaler is None:
            print("❌ Scaler not initialized")
            return
        
        X_scaled = self.scaler.transform(X)
        
        # Train model
        self.train_model(X_scaled)
        
        # Save models
        self.save_models()
        
        print("\n" + "="*60)
        print("✅ TRAINING COMPLETE!")
        print("="*60)
        print("\n📝 Next step: Update detector_server.py with ML code")
        print("   Then run: python detector_server.py")
        
        return (self.model, self.scaler)


# Main execution
if __name__ == "__main__":
    trainer = IsolationForestTrainer()
    
    try:
        result = trainer.full_training_pipeline(
            normal_file='training_data/normal_flows.csv'
        )
        if result is not None:
            model, scaler = result
        else:
            print("❌ Training pipeline failed")
            model, scaler = None, None
        print("\n🎉 Your AI model is ready!")
    except FileNotFoundError:
        print("❌ ERROR: training_data/normal_flows.csv not found!")
        print("   Make sure you ran: python data_generator.py")
    except Exception as e:
        print(f"❌ ERROR: {e}")