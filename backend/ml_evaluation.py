import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import confusion_matrix, classification_report

class ModelEvaluator:
    """Evaluate trained model performance"""
    
    def __init__(self, model_path='isoforest_model.pkl',
                 scaler_path='isoforest_scaler.pkl'):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_cols = ['duration', 'pkt_count', 'byte_count',
                            'src2dst_pkts', 'dst2src_pkts', 'mean_pkt_size',
                            'tcp_syn', 'tcp_rst']
    
    def load_test_data(self, normal_file, attack_file):
        """Load test data"""
        
        normal_df = pd.read_csv(normal_file)
        attack_df = pd.read_csv(attack_file)
        
        normal_df['is_anomaly'] = 0
        attack_df['is_anomaly'] = 1
        
        test_data = pd.concat([normal_df, attack_df], ignore_index=True)
        test_data = test_data.sample(frac=1).reset_index(drop=True)
        
        return test_data
    
    def evaluate_model(self, test_data):
        """Evaluate model on test data"""
        
        X = test_data[self.feature_cols].values
        y_true = test_data['is_anomaly'].values
        
        X_scaled = self.scaler.transform(X)
        
        y_pred = self.model.predict(X_scaled)
        y_pred_binary = (y_pred == -1).astype(int)
        
        print("\n📊 MODEL EVALUATION RESULTS")
        print("="*60)
        
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred_binary).ravel()
        print(f"\n✅ Confusion Matrix:")
        print(f"   True Negatives:  {tn}")
        print(f"   False Positives: {fp}")
        print(f"   False Negatives: {fn}")
        print(f"   True Positives:  {tp}")
        
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        print(f"\n📈 Accuracy: {accuracy:.4f}")
        
        return y_true, y_pred_binary


if __name__ == "__main__":
    evaluator = ModelEvaluator()
    
    test_data = evaluator.load_test_data(
        normal_file='training_data/normal_flows.csv',
        attack_file='training_data/attack_flows.csv'
    )
    
    y_true, y_pred = evaluator.evaluate_model(test_data)
