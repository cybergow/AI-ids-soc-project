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

def enrich_flow(flow):
    """Ensure consistency of derived features"""
    pkt_count = flow.get('pkt_count', 1)
    byte_count = flow.get('byte_count', 60)
    
    # Randomly split packets between src->dst and dst->src
    # Attacks often have more src->dst (e.g. scanning, exploiting)
    ratio = random.uniform(0.6, 1.0)
    src2dst = int(pkt_count * ratio)
    dst2src = pkt_count - src2dst
    
    flow['src2dst_pkts'] = src2dst
    flow['dst2src_pkts'] = dst2src
    
    # Calculate mean packet size
    if pkt_count > 0:
        flow['mean_pkt_size'] = float(byte_count) / float(pkt_count)
    else:
        flow['mean_pkt_size'] = 0.0
        
    return flow

def generate_attack_flow():
    # EXAGGERATED attack patterns to ensure detection
    attacks = [
        {
            "name": "Port Scan (Aggressive)",
            "features": {
                "src_ip": f"192.168.1.{random.randint(2,254)}",
                "dst_ip": f"10.0.0.{random.randint(1,254)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([22, 80, 443, 3389, 21, 23, 135, 445]),
                "proto": 6,
                "pkt_count": 1,  # Single packet
                "byte_count": 40, # Minimal size
                "duration": 0.00001,  # INSTANT
                "flags": 2,  
                "service": "",
                "state": "REQ",
                "ground_truth": 1
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
                "pkt_count": random.randint(10000, 50000),  # HUGE count
                "byte_count": random.randint(10000000, 50000000),  # HUGE bytes
                "duration": random.uniform(10, 20),
                "flags": 24,
                "service": "http",
                "state": "EST",
                "ground_truth": 1
            }
        },
        {
             "name": "C2 Beaconing (Suspicious)",
             "features": {
                 "src_ip": f"192.168.1.{random.randint(2,254)}",
                 "dst_ip": f"185.10.1.{random.randint(1,254)}",
                 "src_port": random.randint(1024, 65535),
                 "dst_port": 8080,
                 "proto": 6,
                 "pkt_count": random.randint(5, 20),
                 "byte_count": random.randint(500, 2000),
                 "duration": random.uniform(30, 60), # Long duration
                 "flags": 2,
                 "service": "http",
                 "state": "EST",
                 "ground_truth": 1
             }
        },
        {
             "name": "SQL Injection Probe",
             "features": {
                 "src_ip": f"192.168.1.{random.randint(2,254)}",
                 "dst_ip": f"10.0.0.{random.randint(1,254)}",
                 "src_port": random.randint(1024, 65535),
                 "dst_port": 80,
                 "proto": 6,
                 "pkt_count": random.randint(3, 8),
                 "byte_count": random.randint(800, 1500), # Suspiciously large requests for few packets
                 "duration": random.uniform(0.1, 0.5),
                 "flags": 24,
                 "service": "http",
                 "state": "EST",
                 "ground_truth": 1
             }
        }
    ]
    
    attack = random.choice(attacks)
    feat = attack["features"]
    feat["reason"] = f"Type: {attack['name']}"
    return enrich_flow(feat)

def generate_benign_flow():
    # Very normal traffic
    flow = {
        "src_ip": f"192.168.1.{random.randint(2,254)}",
        "dst_ip": f"8.8.8.{random.randint(1,254)}",  # DNS
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([53, 443, 80]),
        "proto": random.choice([6, 17]),
        "pkt_count": random.randint(10, 100),
        "byte_count": random.randint(1000, 8000),
        "duration": random.uniform(1.0, 15.0),
        "flags": random.randint(16, 24),
        "service": random.choice(["http", "dns", "ssl"]),
        "state": "EST",
        "ground_truth": 0
    }
    return enrich_flow(flow)

if __name__ == "__main__":
    print("🚀 Sending 200 DISTINCT attack flows + 200 NORMAL benign flows...")
    
    # Send attacks
    print("  Sending attacks...")
    for i in range(200):
        send_flow(generate_attack_flow())
        if i % 20 == 0:
            time.sleep(0.01)
    
    # Send benign
    print("  Sending benign...")
    for i in range(200):
        send_flow(generate_benign_flow())
        if i % 20 == 0:
            time.sleep(0.01)
    
    print("✅ Done! Data sent to localhost:9999")
