# backend/simulate_anomalous_flows.py
import socket, json, time

def send(feat, host='127.0.0.1', port=9999):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(json.dumps(feat).encode(), (host, port))
    s.close()

def main():
    now = time.time()
    benign = {
      "key":["192.168.0.10","10.0.0.2",12345,80,6],
      "src_ip":"192.168.0.10","dst_ip":"10.0.0.2",
      "duration":1.2,"pkt_count":5,"byte_count":500,
      "src2dst_pkts":4,"dst2src_pkts":1,"mean_pkt_size":100,"timestamp": now
    }
    print("Sending one benign flow (control).")
    send(benign); time.sleep(0.4)

    # 1) DoS-like: huge pkt_count and bytes within short duration -> very high pkt_rate
    dos_like = {
      "key":["9.9.9.9","10.0.0.2",40000,80,6],
      "src_ip":"9.9.9.9","dst_ip":"10.0.0.2",
      "duration":0.2,"pkt_count":5000,"byte_count":5000000,
      "src2dst_pkts":4995,"dst2src_pkts":5,"mean_pkt_size":1000,"timestamp": time.time()
    }
    print("Sending DoS-like anomalous flow (very high pkt_count & byte_count).")
    send(dos_like); time.sleep(0.4)

    # 2) Slow/long transfer but huge bytes (unusual pattern)
    big_transfer = {
      "key":["8.8.8.8","10.0.0.2",53,1234,17],
      "src_ip":"8.8.8.8","dst_ip":"10.0.0.2",
      "duration":120.0,"pkt_count":2000,"byte_count":20000000,
      "src2dst_pkts":1990,"dst2src_pkts":10,"mean_pkt_size":10000,"timestamp": time.time()
    }
    print("Sending big-transfer anomalous flow.")
    send(big_transfer); time.sleep(0.4)

    # 3) Very small duration with many packets (burst)
    burst = {
      "key":["7.7.7.7","10.0.0.2",45000,22,6],
      "src_ip":"7.7.7.7","dst_ip":"10.0.0.2",
      "duration":0.01,"pkt_count":2000,"byte_count":1500000,
      "src2dst_pkts":1990,"dst2src_pkts":10,"mean_pkt_size":750,"timestamp": time.time()
    }
    print("Sending burst anomalous flow.")
    send(burst); time.sleep(0.4)

    print("All anomalous flows sent. Check detector logs and dashboard.")

if __name__ == '__main__':
    import time
    main()
