"""
simulate_mitm_dns.py - MITM, ARP Spoofing, DNS Exfiltration
Integrated with detector_server.py via UDP network flows
"""

import socket
import json
import time
import random
import requests

UDP_HOST = '127.0.0.1'
UDP_PORT = 9999
API_URL = 'http://localhost:5000/api'

# ============================================================================
# MITM + DNS ATTACK SIMULATIONS
# ============================================================================

MITM_ATTACKS = [
    {
        'name': 'ARP Spoofing Attack',
        'src_ip': '192.168.1.200',
        'dst_ip': '192.168.1.1',
        'src_port': 0,
        'dst_port': 67,
        'proto': 1,  # ICMP-like for ARP
        'duration': 0.05,
        'pkt_count': 10,
        'byte_count': 500,
        'reason': 'ARP Spoofing - Gateway impersonation',
        'severity': 'HIGH',
        'score': 0.85
    },
    
    {
        'name': 'DNS Spoofing Attack',
        'src_ip': '192.168.1.50',
        'dst_ip': '8.8.8.8',
        'src_port': 53452,
        'dst_port': 53,
        'proto': 17,  # UDP
        'duration': 0.1,
        'pkt_count': 5,
        'byte_count': 200,
        'reason': 'DNS Query to external resolver',
        'severity': 'MEDIUM',
        'score': 0.45
    },
    
    {
        'name': 'DNS Hijacking',
        'src_ip': '192.168.1.100',
        'dst_ip': '1.1.1.1',  # Cloudflare
        'src_port': 54321,
        'dst_port': 53,
        'proto': 17,
        'duration': 0.15,
        'pkt_count': 20,
        'byte_count': 1500,
        'reason': 'Suspicious DNS resolution pattern',
        'severity': 'HIGH',
        'score': 0.78
    },
    
    {
        'name': 'DNS Exfiltration Attempt',
        'src_ip': '192.168.1.105',
        'dst_ip': '203.0.113.50',  # External attacker
        'src_port': 12345,
        'dst_port': 53,
        'proto': 17,
        'duration': 5.0,
        'pkt_count': 500,
        'byte_count': 50000,
        'src2dst_pkts': 300,
        'dst2src_pkts': 200,
        'reason': 'DNS data exfiltration - Large DNS queries',
        'severity': 'CRITICAL',
        'score': 0.92
    },
    
    {
        'name': 'MITM - Traffic Interception',
        'src_ip': '192.168.1.200',
        'dst_ip': '203.0.113.100',
        'src_port': 44444,
        'dst_port': 80,
        'proto': 6,  # TCP
        'duration': 10.0,
        'pkt_count': 1000,
        'byte_count': 500000,
        'src2dst_pkts': 500,
        'dst2src_pkts': 500,
        'reason': 'MITM attack - Suspicious bidirectional traffic',
        'severity': 'CRITICAL',
        'score': 0.95
    },
    
    {
        'name': 'DNS Cache Poisoning',
        'src_ip': '192.168.1.1',  # From gateway (spoofed)
        'dst_ip': '192.168.1.50',
        'src_port': 53,
        'dst_port': 53461,
        'proto': 17,
        'duration': 0.05,
        'pkt_count': 2,
        'byte_count': 200,
        'reason': 'DNS response from unauthorized source',
        'severity': 'CRITICAL',
        'score': 0.88
    },
    
    {
        'name': 'SSRF via DNS Tunneling',
        'src_ip': '10.0.0.5',
        'dst_ip': '8.8.8.8',
        'src_port': 53456,
        'dst_port': 53,
        'proto': 17,
        'duration': 2.5,
        'pkt_count': 150,
        'byte_count': 25000,
        'reason': 'DNS tunneling - Covert command channel',
        'severity': 'HIGH',
        'score': 0.75
    },
    
    {
        'name': 'DGA (Domain Generation Algorithm)',
        'src_ip': '192.168.1.110',
        'dst_ip': '8.8.4.4',
        'src_port': 52000,
        'dst_port': 53,
        'proto': 17,
        'duration': 3.0,
        'pkt_count': 200,
        'byte_count': 15000,
        'reason': 'DGA botnet - Multiple domain lookups',
        'severity': 'CRITICAL',
        'score': 0.91
    }
]

# ============================================================================
# DETECTOR INTEGRATION
# ============================================================================

def send_mitm_flow_udp(flow_data):
    """Send MITM/DNS flow to detector via UDP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Ensure all required fields are present
        severity = str(flow_data.get('severity', 'LOW') or 'LOW').strip().upper()
        score = float(flow_data.get('score', 0.0) or 0.0)
        is_anomaly = bool(flow_data.get('is_anomaly', False) or (severity in ('HIGH', 'CRITICAL')) or (score >= 0.7))

        flow = {
            'src_ip': flow_data.get('src_ip'),
            'dst_ip': flow_data.get('dst_ip'),
            'src_port': flow_data.get('src_port', 0),
            'dst_port': flow_data.get('dst_port', 0),
            'proto': flow_data.get('proto', 6),
            'is_anomaly': is_anomaly,
            'duration': flow_data.get('duration', 0),
            'pkt_count': flow_data.get('pkt_count', 0),
            'byte_count': flow_data.get('byte_count', 0),
            'src2dst_pkts': flow_data.get('src2dst_pkts', flow_data.get('pkt_count', 0) // 2),
            'dst2src_pkts': flow_data.get('dst2src_pkts', flow_data.get('pkt_count', 0) // 2),
            'mean_pkt_size': flow_data.get('mean_pkt_size', flow_data.get('byte_count', 0) / max(flow_data.get('pkt_count', 1), 1)),
            'timestamp': time.time(),
            'reason': flow_data.get('reason', 'Network Flow'),
            'severity': severity,
            'score': score
        }
        
        sock.sendto(json.dumps(flow).encode(), (UDP_HOST, UDP_PORT))
        sock.close()
        
        print(f"  ✅ UDP Sent: {flow['reason']}")
        print(f"     From: {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']}")
        print(f"     Severity: {flow['severity']} | Score: {flow['score']*100:.0f}%")
        
    except Exception as e:
        print(f"  ❌ UDP Error: {e}")

def simulate_mitm_attack(attack_info):
    """Simulate a single MITM/DNS attack"""
    name = attack_info['name']
    
    print(f"\n{'='*70}")
    print(f"🔴 SIMULATING: {name}")
    print(f"{'='*70}")
    print(f"Description: {attack_info['reason']}")
    print(f"Attack Type: {attack_info['severity']}")
    
    # Send to detector
    send_mitm_flow_udp(attack_info)

    try:
        requests.post(
            f'{API_URL}/log-event',
            json={
                'level': 'WARNING',
                'component': 'MITM_DNS_SIM',
                'message': f"Simulated network attack: {name} | {attack_info.get('reason','')}",
                'source': 'simulator'
            },
            timeout=2
        )
    except Exception:
        pass
    
    time.sleep(0.5)

def run_all_mitm_attacks(delay_between=1):
    """Run all MITM/DNS attack simulations"""
    print("\n" + "="*70)
    print("🛡️  MITM + DNS ATTACK SIMULATOR")
    print("="*70)
    print(f"Total attacks: {len(MITM_ATTACKS)}")
    print(f"Delay between attacks: {delay_between}s")
    print("="*70)
    
    for i, attack in enumerate(MITM_ATTACKS, 1):
        print(f"\n[{i}/{len(MITM_ATTACKS)}] Running attack...\n")
        simulate_mitm_attack(attack)
        
        if i < len(MITM_ATTACKS):
            print(f"⏳ Waiting {delay_between}s before next attack...")
            time.sleep(delay_between)
    
    print("\n" + "="*70)
    print("✅ MITM/DNS ATTACK SIMULATION COMPLETE")
    print("="*70)
    print("\n📊 CHECK YOUR DASHBOARD:")
    print("   → Network Alerts: http://localhost:5000")
    print("   → You should see CRITICAL alerts for:")
    print("      • DNS Exfiltration")
    print("      • MITM Traffic")
    print("      • DNS Cache Poisoning")
    print("      • DGA Botnet Activity")
    print("\n")

if __name__ == '__main__':
    import sys
    import requests
    
    print("\n🚀 MITM + DNS Attack Simulator")
    print("UDP Destination:", f"{UDP_HOST}:{UDP_PORT}\n")
    
    # Check if detector is running
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=2)
        print(f"✅ Detector is ONLINE\n")
    except:
        print(f"⚠️  WARNING: Detector not responding!")
        print(f"   Make sure to run: python backend/detector_server.py\n")
        input("Press Enter to continue anyway...")
    
    # Run attacks
    run_all_mitm_attacks(delay_between=1)