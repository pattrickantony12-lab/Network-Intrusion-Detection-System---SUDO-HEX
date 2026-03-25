import random
import socket
from datetime import datetime


class NetworkSimulator:
    def __init__(self):
        self.protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP']
        self.layers = ['Application', 'Transport', 'Network', 'Data Link']
        # Original & Professional Technical Identities
        self.attacks = [
            'Normal',
            'Normal',
            'Normal',  # Reclassified from Port Scan
            'DDoS Attack (TCP-SYN Flood)',
            'Web Attack (XSS Injection)',
            'Brute Force (RDP/SSH)',
            'Backdoor (C2 Trojan Call)',
            'Exploit (Remote Code Execution)'
        ]
        self.local_ip = self._get_local_ip()

        # Precise OSI Layer targeted by each attack type
        self.osi_layer_map = {
            'DDoS Attack (TCP-SYN Flood)':     'Layer 4 - Transport',
            'Web Attack (XSS Injection)':      'Layer 7 - Application',
            'Brute Force (RDP/SSH)':           'Layer 7 - Application',
            'Backdoor (C2 Trojan Call)':       'Layer 5 - Session',
            'Exploit (Remote Code Execution)': 'Layer 6 - Presentation',
            'Normal':                          'Layer 3 - Network',
        }

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "192.168.1.15"  # Realistic fallback

    def generate_ip(self):
        # 192.168.x.x series for local traffic
        if random.random() > 0.4:
            return f"192.168.1.{random.randint(2, 254)}"
        # Standard external ranges
        prefix = random.choice(['103', '45', '185', '77', '212', '142'])
        return f"{prefix}.{random.randint(10, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def get_layer(self, protocol):
        if protocol in ['HTTP', 'HTTPS']: return 'Application'
        if protocol in ['TCP', 'UDP']: return 'Transport'
        return 'Network'

    def get_osi_layer(self, attack_type):
        """Return the precise OSI layer targeted by this attack."""
        return self.osi_layer_map.get(attack_type, 'Layer 3 - Network')

    def generate_packet(self):
        protocol = random.choice(self.protocols)
        attack_type = random.choice(self.attacks)
        layer = self.get_layer(protocol)
        osi_layer = self.get_osi_layer(attack_type)

        is_malicious = 'Normal' not in attack_type

        if is_malicious:
            # External source attacking local host
            prefix = random.choice(['185', '45', '103', '77', '212', '91'])
            src_ip = f"{prefix}.{random.randint(10, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            dst_ip = self.local_ip
            confidence = round(random.uniform(99.6, 99.98), 2)

            # Dynamic Severity Assignment
            if 'DDoS' in attack_type or 'Exploit' in attack_type:
                severity = 'Critical'
            else:
                severity = 'High'
        else:
            src_ip = self.generate_ip()
            dst_ip = self.local_ip if random.random() > 0.5 else f"192.168.1.{random.randint(1, 20)}"
            confidence = round(random.uniform(99.9, 100.0), 2)
            severity = 'None'

        return {
            'timestamp':      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'protocol':       protocol,
            'source_ip':      src_ip,
            'destination_ip': dst_ip,
            'attack_type':    attack_type,
            'network_layer':  layer,
            'osi_layer':      osi_layer,
            'is_malicious':   is_malicious,
            'confidence':     confidence,
            'severity':       severity
        }
