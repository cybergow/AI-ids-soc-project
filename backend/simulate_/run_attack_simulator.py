import sys
import os
import time
import random
import socket
import json
import requests

# Add current directory to path to import sibling scripts
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import simulate_ransomware
    import simulate_fileless
except ImportError:
    print("⚠️  Warning: Could not import sibling simulation scripts.")
    simulate_ransomware = None
    simulate_fileless = None

API_URL = 'http://localhost:5000/api'
UDP_IP = "127.0.0.1"
UDP_PORT = 9999

def send_udp_flow(payload):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(payload).encode(), (UDP_IP, UDP_PORT))
        sock.close()
        print(f"  📡 Sent flow: {payload.get('reason', 'Unknown')}")
    except Exception as e:
        print(f"  ❌ Error sending UDP flow: {e}")

def run_network_attacks():
    print("\n" + "="*70)
    print("🌐 RUNNING NETWORK ATTACKS (UDP Flows)")
    print("="*70)
    
    attacks = [
        {
            "name": "Port Scan (Aggressive)",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": f"10.0.0.{random.randint(1,254)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": 22,
                "proto": 6,
                "pkt_count": 5,
                "byte_count": 200,
                "duration": 0.1,
                "ground_truth": 1,
                "reason": "Type: Port Scan (Aggressive)"
            }
        },
        {
            "name": "Data Exfiltration (Massive)",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": f"203.0.113.{random.randint(1,254)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": 443,
                "proto": 6,
                "pkt_count": 50000,
                "byte_count": 50000000,
                "duration": 15.0,
                "ground_truth": 1,
                "reason": "Type: Data Exfiltration (Massive)"
            }
        },
        {
            "name": "SQL Injection Probe",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": f"10.0.0.80",
                "src_port": random.randint(1024, 65535),
                "dst_port": 80,
                "proto": 6,
                "pkt_count": 10,
                "byte_count": 1200,
                "duration": 0.5,
                "ground_truth": 1,
                "reason": "Type: SQL Injection Probe"
            }
        },
        {
            "name": "C2 Beaconing",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": f"185.100.1.50",
                "src_port": random.randint(1024, 65535),
                "dst_port": 8080,
                "proto": 6,
                "pkt_count": 15,
                "byte_count": 1500,
                "duration": 60.0,
                "ground_truth": 1,
                "reason": "Type: C2 Beaconing"
            }
        }
    ]

    for attack in attacks:
        print(f"\n[Network] Simulating: {attack['name']}")
        # Send 5 bursts of each attack
        for _ in range(5):
            # Minor variations
            payload = attack["features"].copy()
            payload["src_port"] = random.randint(1024, 65535)
            send_udp_flow(payload)
            time.sleep(0.1)
        time.sleep(1)

def main():
    print("\n" + "="*80)
    print("🚀 MASTER ATTACK SIMULATOR 🚀")
    print("="*80)
    print("This script will simulate a full cyber kill chain:")
    print("1. Network Attacks (Port Scan, Exfiltration, SQLi)")
    print("2. Ransomware (File Encryption, Deletion)")
    print("3. Fileless Attacks (PowerShell Injection)")
    print("="*80 + "\n")

    # Check Detector Status
    try:
        requests.get(f'{API_URL}/health', timeout=2)
        print("✅ Detector is ONLINE at", API_URL)
    except:
        print("⚠️  Detector is OFFLINE. Please run 'backend/detector_server.py'")
        print("   Attacks will be sent via UDP nonetheless.")

    # 1. Run Network Attacks
    run_network_attacks()

    # 2. Run Ransomware
    if simulate_ransomware:
        print("\n" + "="*70)
        print("💀 RUNNING RANSOMWARE SIMULATION")
        print("="*70)
        # Select a few random ransomware commands
        cmds = simulate_ransomware.RANSOMWARE_COMMANDS[:2] + simulate_ransomware.RANSOMWARE_COMMANDS[-2:]
        for cmd in cmds:
            simulate_ransomware.simulate_ransomware_attack(cmd)
            time.sleep(1)
        
        # C2 Flows
        for flow in simulate_ransomware.C2_FLOWS[:2]:
            simulate_ransomware.simulate_c2_communication(flow)
            time.sleep(1)

    # 3. Run Fileless
    if simulate_fileless:
        print("\n" + "="*70)
        print("👻 RUNNING FILELESS ATTACK SIMULATION")
        print("="*70)
        payloads = simulate_fileless.FILELESS_PAYLOADS[:3]
        for p in payloads:
            simulate_fileless.simulate_fileless_attack(p)
            time.sleep(1)

    print("\n" + "="*80)
    print("✅ SIMULATION COMPLETE")
    print("="*80)
    print("Please check the dashboard at http://localhost:5000")
    print("You should see alerts in 'Network Alerts', 'CMD History', and 'System Logs'.")

if __name__ == "__main__":
    main()
