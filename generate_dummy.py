from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
import time

packets = []

# 1. Normal Trafik
for i in range(10):
    packets.append(IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com")))

# 2. DNS Tunneling Anomaly (Over 50 requests)
for i in range(60):
    packets.append(IP(src="10.10.10.10", dst="1.1.1.1") / UDP(sport=4321, dport=53) / DNS(rd=1, qd=DNSQR(qname="malicious-tunnel.com")))

# 3. SYN Flood (Over 100 requests)
for i in range(110):
    packets.append(IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=5555, dport=80, flags="S"))

# 4. HTTP DPI Anomaly (SQL Injection)
packets.append(IP(src="172.16.0.5", dst="192.168.1.200") / TCP(sport=3333, dport=80, flags="PA") / Raw(load="GET /index.php?id=1' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n"))

# 5. Data Exfiltration (Large Payload)
# To simulate, we just need the IP packet to pretend it's big, or we can just send a lot of raw data
large_data = b"X" * 60000  # 60 KB
packets.append(IP(src="10.0.0.5", dst="1.2.3.4") / TCP(sport=4444, dport=443, flags="PA") / Raw(load=large_data))

# 6. GeoIP Test
packets.append(IP(src="104.21.43.12", dst="192.168.1.100") / TCP(sport=80, dport=54321, flags="SA"))

wrpcap("dummy.pcap", packets)
print("Dummy PCAP created.")
