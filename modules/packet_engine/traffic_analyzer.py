# -*- coding: utf-8 -*-
from collections import defaultdict
from core import config as Ayarlar
import logging

logger = logging.getLogger("TrafficAnalyzer")

class TrafficAnalyzer:
    """
    Ağ trafiğindeki paket listesini alarak istatistik çıkaran
    ve olası anomalileri tespit eden motor.
    """

    def __init__(self, packets: list):
        self.packets = packets
        self.ip_frequencies = defaultdict(int)
        self.protocol_distribution = defaultdict(int)
        
        # Anomali tespiti için veri yapıları
        # Hangi IP, hangi portlara gitmiş?
        self.ip_to_ports = defaultdict(set)
        # Hangi IP kaç kez DNS sorgusu yapmış?
        self.dns_requests = defaultdict(int)

    def analyze(self) -> dict:
        if not self.packets:
            logger.warning("Analiz edilecek paket bulunamadı.")
            return {}

        logger.info(f"Trafik analizi başlatılıyor... Toplam paket: {len(self.packets)}")

        for pkt in self.packets:
            src_ip = pkt.get("src_ip")
            dst_port = pkt.get("dst_port")
            protocol = pkt.get("protocol")

            # Genel istatistikler
            self.ip_frequencies[src_ip] += 1
            self.protocol_distribution[protocol] += 1

            # Anomali tespiti için verileri topla
            if dst_port:
                self.ip_to_ports[src_ip].add(dst_port)
            
            if protocol == "DNS":
                self.dns_requests[src_ip] += 1

        # Analiz sonuçlarını hazırla
        results = {
            "total_packets": len(self.packets),
            "top_talkers": self._get_top_talkers(),
            "protocol_distribution": dict(self.protocol_distribution),
            "anomalies": self._detect_anomalies()
        }

        logger.info("Trafik analizi tamamlandı.")
        return results

    def _get_top_talkers(self, limit: int = 5) -> dict:
        """En çok paket gönderen IP'leri döndürür."""
        sorted_ips = sorted(self.ip_frequencies.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_ips[:limit])

    def _detect_anomalies(self) -> list:
        anomalies = []

        # 1. Port Scan Tespiti
        port_scan_threshold = getattr(Ayarlar, "PORT_SCAN_THRESHOLD", 15)
        for ip, ports in self.ip_to_ports.items():
            if len(ports) > port_scan_threshold:
                anomalies.append({
                    "type": "PORT_SCAN",
                    "source_ip": ip,
                    "details": f"{len(ports)} farklı porta erişim denemesi (Eşik: {port_scan_threshold})"
                })

        # 2. DNS Tunneling Tespiti
        dns_threshold = getattr(Ayarlar, "DNS_TUNNELING_THRESHOLD", 50)
        for ip, req_count in self.dns_requests.items():
            if req_count > dns_threshold:
                anomalies.append({
                    "type": "DNS_TUNNELING_SUSPICION",
                    "source_ip": ip,
                    "details": f"{req_count} adet DNS isteği tespit edildi (Eşik: {dns_threshold})"
                })

        return anomalies
