"""
simulate_ransomware.py - Mass Encryption/Deletion, C2 Communication
Integrated with detector_server.py via HTTP API + UDP flows
Shows alerts in CMD History + Network Alerts + System Logs
"""

import requests
import socket
import json
import time

API_URL = 'http://localhost:5000/api'
UDP_HOST = '127.0.0.1'
UDP_PORT = 9999

# ============================================================================
# RANSOMWARE ATTACK SIMULATIONS
# ============================================================================

RANSOMWARE_COMMANDS = [
    {
        'name': 'Mass File Deletion - Documents',
        'command': 'cmd /c del /q /f /s C:\\Users\\*\\Documents\\*',
        'description': 'Delete all documents in user folders',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Recursive Directory Deletion',
        'command': 'powershell -Command "Get-ChildItem C:\\ -Recurse -Force | Where-Object {$_.Extension -in @(\'.doc\',\'.docx\',\'.xls\',\'.xlsx\',\'.pdf\',\'.jpg\',\'.png\')} | Remove-Item -Force"',
        'description': 'Recursively delete files by extension',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Disk Wipe - cipher /w',
        'command': 'cipher /w:C:\\Users\\gowtham\\Documents',
        'description': 'Wipe free disk space to remove file recovery',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Volume Shadow Copy Deletion',
        'command': 'cmd /c vssadmin delete shadows /all /quiet',
        'description': 'Delete VSS backups to prevent recovery',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Boot Sector Encryption',
        'command': 'cmd /c diskpart /s encrypt_boot.txt',
        'description': 'Encrypt boot sector for ransom',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'File Encryption - AES256',
        'command': 'powershell -Command "[System.IO.Directory]::GetFiles(\'C:\\\') | ForEach-Object { Encrypt-File $_ }"',
        'description': 'Encrypt files with AES-256 algorithm',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Backup Deletion - Windows Backup',
        'command': 'cmd /c wbadmin delete catalog -quiet',
        'description': 'Delete Windows backup catalog',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Registry Modification - Disable Recovery',
        'command': 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Ransomware /t REG_SZ /d "powershell -enc JABhID0gMjAwMzs="',
        'description': 'Registry persistence for ransomware',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Ransom Note Creation',
        'command': 'cmd /c copy nul C:\\Users\\Public\\Desktop\\README.txt & echo Your files have been encrypted! >> C:\\Users\\Public\\Desktop\\README.txt',
        'description': 'Create ransom note on desktop',
        'severity': 'HIGH'
    },
    
    {
        'name': 'Network Share Encryption Spread',
        'command': 'powershell -Command "net view | ForEach-Object { Copy-Item C:\\payload.exe \\\\$_\\c$\\ -Force; Invoke-Command -ComputerName $_ -ScriptBlock { C:\\payload.exe } }"',
        'description': 'Spread ransomware to network shares',
        'severity': 'CRITICAL'
    }
]

# ============================================================================
# C2 COMMUNICATION FLOWS
# ============================================================================

C2_FLOWS = [
    {
        'name': 'C2 Connection - Initial Beacon',
        'src_ip': '192.168.1.100',
        'dst_ip': '203.0.113.10',
        'dst_port': 443,
        'reason': 'Ransomware C2 beacon',
        'severity': 'CRITICAL',
        'score': 0.95
    },
    
    {
        'name': 'C2 Data Exfiltration',
        'src_ip': '192.168.1.100',
        'dst_ip': '203.0.113.10',
        'dst_port': 8443,
        'reason': 'Large data transfer to C2 server',
        'severity': 'CRITICAL',
        'score': 0.98
    },
    
    {
        'name': 'C2 Command Reception',
        'src_ip': '203.0.113.10',
        'dst_ip': '192.168.1.100',
        'dst_port': 54321,
        'reason': 'C2 command reception from attacker',
        'severity': 'CRITICAL',
        'score': 0.96
    },
    
    {
        'name': 'Ransom Payment Communication',
        'src_ip': '192.168.1.100',
        'dst_ip': '198.51.100.50',
        'dst_port': 80,
        'reason': 'HTTP communication to ransom payment page',
        'severity': 'CRITICAL',
        'score': 0.94
    }
]

# ============================================================================
# DETECTOR INTEGRATION
# ============================================================================

def send_ransomware_cmd_to_detector(cmd_info):
    """Send ransomware command to detector via HTTP API"""
    try:
        response = requests.post(
            f'{API_URL}/test-cmd',
            json={
                'command': cmd_info['command'],
                'method': 'hybrid',
                'source': 'ransomware_simulator',
                'description': cmd_info['description']
            },
            timeout=5
        )
        
        result = response.json()
        
        print(f"\n  ✅ HTTP API Response:")
        print(f"     Is Malicious: {result.get('ismalicious')}")
        print(f"     Severity: {result.get('severity', 'N/A').upper()}")
        print(f"     Confidence: {result.get('confidence', 0)*100:.1f}%")
        print(f"     Reason: {result.get('reason', 'Detection pattern matched')}")
        
        return result
        
    except Exception as e:
        print(f"\n  ❌ HTTP Error: {e}")
        return None

def send_c2_flow_udp(flow_info):
    """Send C2 communication flow via UDP"""
    try:
        flow = {
            'src_ip': flow_info['src_ip'],
            'dst_ip': flow_info['dst_ip'],
            'src_port': flow_info.get('src_port', 54321),
            'dst_port': flow_info.get('dst_port', 443),
            'proto': 6,  # TCP
            'duration': 10.0,
            'pkt_count': 500,
            'byte_count': 1000000,  # 1MB for exfiltration
            'src2dst_pkts': 300,
            'dst2src_pkts': 200,
            'mean_pkt_size': 2000,
            'timestamp': time.time(),
            'reason': flow_info['reason'],
            'severity': flow_info['severity'],
            'score': flow_info['score']
        }
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(flow).encode(), (UDP_HOST, UDP_PORT))
        sock.close()
        
        print(f"  📡 C2 Flow sent: {flow['reason']}")
        print(f"     From: {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']}")
        print(f"     Data: {flow['byte_count']/1000000:.1f}MB | Severity: {flow['severity']}")
        
    except Exception as e:
        print(f"  ⚠️  Could not send C2 flow: {e}")

def simulate_ransomware_attack(cmd_info):
    """Simulate a single ransomware command execution"""
    name = cmd_info['name']
    
    print(f"\n{'='*70}")
    print(f"💰 SIMULATING: {name}")
    print(f"{'='*70}")
    print(f"Description: {cmd_info['description']}")
    print(f"Severity: {cmd_info['severity']}")
    print(f"Command: {cmd_info['command'][:60]}...")
    print(f"{'='*70}")
    
    # Send to detector via HTTP
    print(f"\n1️⃣  Sending command to detector...")
    send_ransomware_cmd_to_detector(cmd_info)
    
    time.sleep(0.5)

def simulate_c2_communication(flow_info):
    """Simulate C2 communication"""
    print(f"\n{'='*70}")
    print(f"🔗 SIMULATING: {flow_info['name']}")
    print(f"{'='*70}")
    print(f"Description: {flow_info['reason']}")
    print(f"From: {flow_info['src_ip']} → {flow_info['dst_ip']}:{flow_info['dst_port']}")
    print(f"{'='*70}")
    
    # Send C2 flow
    print(f"\n1️⃣  Sending C2 flow to detector...")
    send_c2_flow_udp(flow_info)
    
    time.sleep(0.5)

def run_ransomware_simulation(delay_between=1):
    """Run complete ransomware attack simulation"""
    print("\n" + "="*70)
    print("🛡️  RANSOMWARE ATTACK SIMULATOR")
    print("="*70)
    print(f"Total commands: {len(RANSOMWARE_COMMANDS)}")
    print(f"Total C2 flows: {len(C2_FLOWS)}")
    print(f"Delay between attacks: {delay_between}s")
    print("="*70)
    
    # Phase 1: Reconnaissance and persistence
    print("\n" + "="*70)
    print("PHASE 1: RECONNAISSANCE & PERSISTENCE")
    print("="*70)
    for i, cmd_info in enumerate(RANSOMWARE_COMMANDS[:3], 1):
        print(f"\n[Phase 1 - {i}/3] Running attack...\n")
        simulate_ransomware_attack(cmd_info)
        if i < 3:
            print(f"⏳ Waiting {delay_between}s before next command...")
            time.sleep(delay_between)
    
    # Phase 2: C2 Communication
    print("\n" + "="*70)
    print("PHASE 2: C2 COMMUNICATION")
    print("="*70)
    for i, flow_info in enumerate(C2_FLOWS, 1):
        print(f"\n[Phase 2 - {i}/{len(C2_FLOWS)}] Establishing C2...\n")
        simulate_c2_communication(flow_info)
        if i < len(C2_FLOWS):
            print(f"⏳ Waiting {delay_between}s before next beacon...")
            time.sleep(delay_between)
    
    # Phase 3: File encryption and deletion
    print("\n" + "="*70)
    print("PHASE 3: ENCRYPTION & DELETION")
    print("="*70)
    for i, cmd_info in enumerate(RANSOMWARE_COMMANDS[3:], 1):
        print(f"\n[Phase 3 - {i}/{len(RANSOMWARE_COMMANDS)-3}] Running attack...\n")
        simulate_ransomware_attack(cmd_info)
        if i < len(RANSOMWARE_COMMANDS) - 3:
            print(f"⏳ Waiting {delay_between}s before next command...")
            time.sleep(delay_between)
    
    print("\n" + "="*70)
    print("✅ RANSOMWARE SIMULATION COMPLETE")
    print("="*70)
    print("\n📊 CHECK YOUR DASHBOARD:")
    print("   → Dashboard: http://localhost:5000")
    print("   → CMD History: http://localhost:5000/cmd-history")
    print("   → System Logs: http://localhost:5000/system-logs")
    print("\n   You should see:")
    print("      • 10 CRITICAL malicious commands (file deletion, encryption)")
    print("      • 4 CRITICAL network flows (C2 communication)")
    print("      • Detection confidence: 90-98%")
    print("      • Total alerts: 14")
    print("\n")

if __name__ == '__main__':
    import sys
    
    print("\n🚀 Ransomware Attack Simulator")
    print("API Endpoint:", API_URL)
    print("UDP Listener:", f"{UDP_HOST}:{UDP_PORT}\n")
    
    # Check if detector is running
    try:
        response = requests.get(f'{API_URL}/health', timeout=2)
        health = response.json()
        print(f"✅ Detector is ONLINE")
        print(f"   ML Mode: {health.get('ml_mode', 'unknown')}")
        print(f"   Patterns: {health.get('cmd_patterns', 0)}\n")
    except Exception as e:
        print(f"⚠️  WARNING: Detector not responding!")
        print(f"   Error: {e}")
        print(f"   Make sure to run: python backend/detector_server.py\n")
        input("Press Enter to continue anyway...")
    
    # Run ransomware simulation
    run_ransomware_simulation(delay_between=1)