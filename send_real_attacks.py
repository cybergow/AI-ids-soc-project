#!/usr/bin/env python3
"""
Send realistic attack flows with ground_truth=1 to test detection
"""
import socket
import json
import time
import random

UDP_IP = "127.0.0.1"
UDP_PORT = 9999

def send_flow(payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(json.dumps(payload).encode(), (UDP_IP, UDP_PORT))
    sock.close()

def generate_attack_flow():
    # Realistic attack patterns
    attacks = [
        {
            "name": "Port Scan",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": f"10.0.0.{random.randint(1,254)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([22, 80, 443, 3389, 21, 23, 135, 445]),
                "proto": 6,
                "pkt_count": random.randint(1, 3),  # Port scans have few packets
                "byte_count": random.randint(40, 200),
                "duration": random.uniform(0.01, 0.1),  # Very short
                "flags": 2,  # SYN flag
                "service": "",
                "state": "REQ",
                "ground_truth": 1
            }
        },
        {
            "name": "Data Exfiltration",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": f"203.0.113.{random.randint(1,254)}",  # External IP
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([443, 80, 22]),
                "proto": 6,
                "pkt_count": random.randint(500, 2000),  # High packet count
                "byte_count": random.randint(100000, 1000000),  # Large bytes
                "duration": random.uniform(60, 300),  # Long duration
                "flags": 24,  # PSH, ACK
                "service": "http",
                "state": "EST",
                "ground_truth": 1
            }
        },
        {
            "name": "Brute Force SSH",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": "192.168.1.1",  # Router/gateway
                "src_port": random.randint(1024, 65535),
                "dst_port": 22,
                "proto": 6,
                "pkt_count": random.randint(20, 100),
                "byte_count": random.randint(1000, 5000),
                "duration": random.uniform(5, 30),
                "flags": 18,  # SYN, ACK
                "service": "ssh",
                "state": "EST",
                "ground_truth": 1
            }
        }
    ]
    
    attack = random.choice(attacks)
    return attack["features"]

def generate_benign_flow():
    return {
        "src_ip": f"192.168.1.{random.randint(2,254)}",
        "dst_ip": f"8.8.8.{random.randint(1,254)}",  # DNS
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([53, 443, 80]),
        "proto": random.choice([6, 17]),
        "pkt_count": random.randint(5, 50),
        "byte_count": random.randint(500, 5000),
        "duration": random.uniform(0.5, 5.0),
        "flags": random.randint(16, 24),
        "service": random.choice(["http", "dns", ""]),
        "state": random.choice(["EST", "FIN"]),
        "ground_truth": 0
    }

if __name__ == "__main__":
    print("🚀 Sending 50 attack flows + 50 benign flows...")
    
    # Send attacks
    for i in range(50):
        send_flow(generate_attack_flow())
        time.sleep(0.1)
    
    # Send benign
    for i in range(50):
        send_flow(generate_benign_flow())
        time.sleep(0.1)
    
    print("✅ Done! Refresh dashboard to see real detection metrics.")
