from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP
import time
import threading
import json
import socket

FLOW_TIMEOUT = 10  # seconds; adjust for faster testing
EMIT_INTERVAL = 1.0  # seconds; emit periodic updates for active flows
flows = {}
lock = threading.Lock()
stop_event = threading.Event()

def make_key(pkt):
    ip = pkt.getlayer(IP)
    if not ip: return None
    sport = getattr(pkt, 'sport', 0)
    dport = getattr(pkt, 'dport', 0)
    return (ip.src, ip.dst, sport, dport, ip.proto)

def update_flow(key, pkt):
    t = time.time()
    with lock:
        f = flows.setdefault(key, {'first_ts':t, 'last_ts':t, 'last_emit':0.0, 'pkt_count':0, 'byte_count':0, 'src2dst_pkts':0, 'dst2src_pkts':0, 'pkt_sizes':[]})
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
    while not stop_event.is_set():
        now = time.time()
        with lock:
            to_remove = []
            for k, f in list(flows.items()):
                should_emit = (now - float(f.get('last_emit', 0.0))) >= EMIT_INTERVAL
                is_expired = (now - f['last_ts']) > FLOW_TIMEOUT
                if should_emit or is_expired:
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
                    f['last_emit'] = now
                if is_expired:
                    to_remove.append(k)
            for k in to_remove:
                flows.pop(k, None)
        time.sleep(0.25)

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

def start_capture(interface=None, udp_addr=('127.0.0.1', 9999), l3_socket=True):
    if l3_socket:
        try:
            conf.use_pcap = True
        except Exception:
            pass
    stop_event.clear()
    threading.Thread(target=flush_old_flows, args=(lambda feat: send_udp(feat, udp_addr),), daemon=True).start()
    sniff(prn=packet_cb, store=False, iface=interface, stop_filter=lambda pkt: stop_event.is_set())

def stop_capture():
    stop_event.set()

if __name__ == '__main__':
    print("Starting flow extractor. (May need root/admin for sniffing)")
    print("Configuring for Layer 3 sniffing (no WinPcap required).")
    start_capture()