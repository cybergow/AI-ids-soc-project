#!/usr/bin/env python3
"""
Send a few sample labeled flows via UDP to populate model metrics.
Run this while detector_server.py is running.
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

def generate_flow(is_attack: bool):
    base = {
        "src_ip": f"192.168.1.{random.randint(2,254)}",
        "dst_ip": f"10.0.0.{random.randint(1,254)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([22, 80, 443, 3389, 21, 23]),
        "proto": random.choice(["TCP", "UDP"]),
        "pkt_count": random.randint(1, 200),
        "byte_count": random.randint(64, 15000),
        "duration": random.uniform(0.1, 5.0),
        "flags": random.randint(0, 255),
        "service": random.choice(["http", "ssh", "dns", "smtp", "ftp", ""]),
        "state": random.choice(["EST", "FIN", "INT", "REQ", ""]),
    }
    if is_attack:
        base["ground_truth"] = 1
        # Simulate attack-like features
        base["dst_port"] = random.choice([22, 3389, 21, 23])
        base["pkt_count"] = random.randint(200, 2000)
        base["byte_count"] = random.randint(5000, 50000)
    else:
        base["ground_truth"] = 0
    return base

if __name__ == "__main__":
    print("Sending 30 labeled flows (15 attack, 15 benign)...")
    for i in range(15):
        send_flow(generate_flow(is_attack=True))
        time.sleep(0.2)
        send_flow(generate_flow(is_attack=False))
        time.sleep(0.2)
    print("Done. Refresh the dashboard to see metrics.")
