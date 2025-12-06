import csv
import random
import os

class NetworkFlowGenerator:
    """Generate synthetic network flows for training"""
    
    def __init__(self):
        self.normal_flows = []
        self.attack_flows = []
    
    def generate_normal_flow(self):
        """Generate normal network flow"""
        return {
            'duration': round(random.uniform(0.5, 300), 2),
            'pkt_count': random.randint(50, 5000),
            'byte_count': random.randint(1000, 10000000),
            'src2dst_pkts': random.randint(25, 2500),
            'dst2src_pkts': random.randint(25, 2500),
            'mean_pkt_size': round(random.uniform(500, 1500), 2),
            'tcp_syn': random.randint(0, 1),
            'tcp_rst': random.randint(0, 5),
            'label': 'normal'
        }
    
    def generate_port_scan_flow(self):
        return {
            'duration': round(random.uniform(0.01, 0.5), 3),
            'pkt_count': random.randint(2, 10),
            'byte_count': random.randint(100, 500),
            'src2dst_pkts': random.randint(5, 10),
            'dst2src_pkts': random.randint(0, 3),
            'mean_pkt_size': round(random.uniform(50, 100), 2),
            'tcp_syn': random.randint(2, 10),
            'tcp_rst': random.randint(1, 8),
            'label': 'port_scan'
        }
    
    def generate_ddos_flow(self):
        return {
            'duration': round(random.uniform(1, 10), 2),
            'pkt_count': random.randint(5000, 50000),
            'byte_count': random.randint(1000000, 500000000),
            'src2dst_pkts': random.randint(3000, 30000),
            'dst2src_pkts': random.randint(0, 100),
            'mean_pkt_size': round(random.uniform(50, 200), 2),
            'tcp_syn': random.randint(5, 20),
            'tcp_rst': random.randint(0, 5),
            'label': 'ddos'
        }
    
    def generate_training_dataset(self, num_normal=5000, num_attacks=1000):
        print(f"Generating {num_normal} normal flows...")
        self.normal_flows = [self.generate_normal_flow() for _ in range(num_normal)]
        
        print(f"Generating {num_attacks} port scan flows...")
        port_scans = [self.generate_port_scan_flow() for _ in range(num_attacks)]
        
        print(f"Generating {num_attacks} DDoS flows...")
        ddos_flows = [self.generate_ddos_flow() for _ in range(num_attacks)]
        
        self.attack_flows = port_scans + ddos_flows
        return self.normal_flows, self.attack_flows
    
    def save_to_csv(self, normal_file='training_data/normal_flows.csv', 
                    attack_file='training_data/attack_flows.csv'):
        os.makedirs('training_data', exist_ok=True)
        
        # Get fieldnames from first element
        fieldnames = list(self.normal_flows[0].keys()) if self.normal_flows else []
        
        with open(normal_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.normal_flows)
        
        print(f"✅ Saved {len(self.normal_flows)} normal flows")
        
        # Get fieldnames from first attack flow
        attack_fieldnames = list(self.attack_flows[0].keys()) if self.attack_flows else []
        
        with open(attack_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=attack_fieldnames)
            writer.writeheader()
            writer.writerows(self.attack_flows)
        
        print(f"✅ Saved {len(self.attack_flows)} attack flows")

if __name__ == "__main__":
    generator = NetworkFlowGenerator()
    normal, attacks = generator.generate_training_dataset(num_normal=5000, num_attacks=1000)
    generator.save_to_csv()
    print(f"\n✅ Total: {len(normal) + len(attacks)} flows generated")
