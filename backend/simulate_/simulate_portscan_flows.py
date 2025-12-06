# backend/simulate_portscan_flows.py
import socket, json, time

def send(feat, host='127.0.0.1', port=9999):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(json.dumps(feat).encode(), (host, port))
    s.close()

def main():
    src = "192.168.0.200"
    dst = "10.0.0.2"
    print("Simulating port scan (30 ports)...")
    for p in range(20000, 200030):   # 30 different destination ports
        feat = {
          "key":[src,dst,4321,p,6],
          "src_ip":src,"dst_ip":dst,
          "src_port":4321,
          "dst_port":p,
          "proto":6,
          "duration":0.05,
          "pkt_count":1,
          "byte_count":60,
          "src2dst_pkts":1,
          "dst2src_pkts":0,
          "mean_pkt_size":60,
          "timestamp": time.time()
        }
        send(feat)
        time.sleep(0.03)   # 30 ms between sends
    print("Port-scan-like flows sent.")
if __name__ == '__main__':
    main()
