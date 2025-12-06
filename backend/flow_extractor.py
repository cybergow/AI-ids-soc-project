from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import time
import threading
import json
import socket

FLOW_TIMEOUT = 10  # seconds; adjust for faster testing
flows = {}
lock = threading.Lock()

def make_key(pkt):
    ip = pkt.getlayer(IP)
    if not ip: return None
    sport = getattr(pkt, 'sport', 0)
    dport = getattr(pkt, 'dport', 0)
    return (ip.src, ip.dst, sport, dport, ip.proto)

def update_flow(key, pkt):
    t = time.time()
    with lock:
        f = flows.setdefault(key, {'first_ts':t, 'last_ts':t, 'pkt_count':0, 'byte_count':0, 'src2dst_pkts':0, 'dst2src_pkts':0, 'pkt_sizes':[]})
        f['last_ts'] = t
        size = len(pkt)
        f['pkt_count'] += 1
        f['byte_count'] += size
        f['pkt_sizes'].append(size)
        if pkt[IP].src == key[0]:
            f['src2dst_pkts'] += 1
        else:
            f['dst2src_pkts'] += 1

def flush_old_flows(cb):
    while True:
        now = time.time()
        with lock:
            old = [k for k,v in list(flows.items()) if now - v['last_ts'] > FLOW_TIMEOUT]
            for k in old:
                f = flows.pop(k)
                duration = max(0.001, f['last_ts'] - f['first_ts'])
                mean_pkt = sum(f['pkt_sizes'])/len(f['pkt_sizes']) if f['pkt_sizes'] else 0
                feat = {
                    'key': k,
                    'src_ip': k[0], 'dst_ip': k[1],
                    'src_port': k[2], 'dst_port': k[3], 'proto': k[4],
                    'duration': duration,
                    'pkt_count': f['pkt_count'],
                    'byte_count': f['byte_count'],
                    'src2dst_pkts': f['src2dst_pkts'],
                    'dst2src_pkts': f['dst2src_pkts'],
                    'mean_pkt_size': mean_pkt,
                    'timestamp': now
                }
                cb(feat)
        time.sleep(1)

def packet_cb(pkt):
    k = make_key(pkt)
    if k:
        update_flow(k, pkt)

def send_udp(feat, addr=('127.0.0.1',9999)):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = json.dumps(feat).encode()
    s.sendto(msg, addr)
    s.close()
    print(f"[extractor] sent flow {feat.get('src_ip')} -> {feat.get('dst_ip')} pkt_count={feat.get('pkt_count')}")

if __name__ == '__main__':
    print("Starting flow extractor. (May need root/admin for sniffing)")
    threading.Thread(target=flush_old_flows, args=(send_udp,), daemon=True).start()
    sniff(prn=packet_cb, store=False)  # optionally add iface="Ethernet" or your interface name