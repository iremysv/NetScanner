# -*- coding: utf-8 -*-
import logging
import requests
import ipaddress
from collections import defaultdict
from core import config as Ayarlar

logger = logging.getLogger("TrafficAnalyzer")


class TrafficAnalyzer:
    """
    Ağ trafiğindeki paket listesini alarak istatistik çıkaran,
    Gelişmiş Anomali Tespiti (SYN Flood, DPI, Exfiltration) yapan
    ve GeoIP destekli motor.
    """

    def __init__(self, packets: list) -> None:
        self.packets = packets
        self.ip_frequencies: defaultdict[str, int] = defaultdict(int)
        self.protocol_distribution: defaultdict[str, int] = defaultdict(int)

        # Anomali tespiti için veri yapıları
        self.ip_to_ports: defaultdict[str, set[int]] = defaultdict(set)
        self.dns_requests: defaultdict[str, int] = defaultdict(int)
        self.syn_counts: defaultdict[str, int] = defaultdict(int)
        self.large_transfers: list[tuple[str, str, int]] = []

        # DPI için (Şüpheli Payload ve DNS tünelleme)
        self.suspicious_dns: list[tuple[str, str]] = []
        self.suspicious_http: list[tuple[str, str]] = []

        # GeoIP Önbelleği (Gereksiz istekleri engellemek için)
        self.geoip_cache: dict[str, str] = {}

    def analyze(self) -> dict:
        if not self.packets:
            logger.warning("Analiz edilecek paket bulunamadı.")
            return {}

        logger.info(
            f"Derin Paket Analizi başlatılıyor... Toplam paket: {len(self.packets)}"
        )

        large_payload_thresh = getattr(Ayarlar, "LARGE_PAYLOAD_THRESHOLD", 50000)

        for pkt in self.packets:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            dst_port = pkt.get("dst_port")
            protocol = pkt.get("protocol")
            flags = pkt.get("flags", "")
            length = pkt.get("length", 0)
            payload = pkt.get("payload_preview")
            dns_query = pkt.get("dns_query")

            if not src_ip:
                continue

            # Genel istatistikler
            self.ip_frequencies[src_ip] += 1
            self.protocol_distribution[protocol] += 1

            # Port Scan Verisi
            if dst_port:
                self.ip_to_ports[src_ip].add(dst_port)

            # DNS Tunneling Verisi
            if protocol == "DNS":
                self.dns_requests[src_ip] += 1
                if dns_query and len(dns_query) > 50:
                    self.suspicious_dns.append((src_ip, dns_query))

            # SYN Flood Verisi
            if "S" in flags and "A" not in flags:
                self.syn_counts[src_ip] += 1

            # Data Exfiltration (Büyük Veri Aktarımı)
            if length > large_payload_thresh:
                self.large_transfers.append((src_ip, dst_ip, length))

            # HTTP DPI Anomaly (Örn: Basit sql/xss veya bot kontrolü)
            if protocol == "HTTP" and payload:
                payload_lower = payload.lower()
                if (
                    "sql" in payload_lower
                    or "script" in payload_lower
                    or "curl" in payload_lower
                ):
                    self.suspicious_http.append((src_ip, payload))

        # En aktif 10 IP'nin konumlarını OSINT ile bul
        top_talkers = self._get_top_talkers(10)
        top_talkers_with_geo = self._enrich_with_geoip(top_talkers)

        # Analiz sonuçlarını hazırla
        results = {
            "total_packets": len(self.packets),
            "top_talkers": top_talkers_with_geo,
            "protocol_distribution": dict(self.protocol_distribution),
            "anomalies": self._detect_anomalies(),
        }

        logger.info("Trafik analizi tamamlandı.")
        return results

    def _get_top_talkers(self, limit: int = 10) -> dict:
        sorted_ips = sorted(
            self.ip_frequencies.items(), key=lambda x: x[1], reverse=True
        )
        return dict(sorted_ips[:limit])

    def _get_geoip(self, ip_str: str) -> str:
        """IP adresinin ülkesini API üzerinden sorgular."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback:
                return "Yerel Ağ (Local)"
        except ValueError:
            return "Geçersiz IP"

        if ip_str in self.geoip_cache:
            return self.geoip_cache[ip_str]

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_str}?fields=country,city", timeout=2
            )
            if response.status_code == 200:
                data = response.json()
                location = (
                    f"{data.get('country', 'Bilinmiyor')} - {data.get('city', '')}"
                )
                self.geoip_cache[ip_str] = location
                return location
        except Exception as e:
            logger.debug(f"GeoIP sorgusu başarısız: {e}")

        self.geoip_cache[ip_str] = "Sorgulanamadı"
        return "Sorgulanamadı"

    def _enrich_with_geoip(self, top_talkers: dict) -> list:
        enriched = []
        for ip, count in top_talkers.items():
            loc = self._get_geoip(ip)
            enriched.append({"ip": ip, "count": count, "location": loc})
        return enriched

    def _detect_anomalies(self) -> list:
        anomalies = []

        # 1. Port Scan Tespiti
        port_scan_threshold = getattr(Ayarlar, "PORT_SCAN_THRESHOLD", 15)
        for ip, ports in self.ip_to_ports.items():
            if len(ports) > port_scan_threshold:
                anomalies.append(
                    {
                        "type": "PORT_SCAN",
                        "source_ip": ip,
                        "details": f"{len(ports)} farklı porta erişim denemesi tespit edildi.",
                    }
                )

        # 2. DNS Tunneling Tespiti
        dns_threshold = getattr(Ayarlar, "DNS_TUNNELING_THRESHOLD", 50)
        for ip, req_count in self.dns_requests.items():
            if req_count > dns_threshold:
                anomalies.append(
                    {
                        "type": "DNS_TUNNELING_SUSPICION",
                        "source_ip": ip,
                        "details": f"{req_count} adet anormal DNS isteği tespit edildi.",
                    }
                )

        for ip, domain in self.suspicious_dns:
            anomalies.append(
                {
                    "type": "DNS_DPI_ANOMALY",
                    "source_ip": ip,
                    "details": f"Şüpheli (çok uzun) DNS sorgusu: {domain}",
                }
            )

        # 3. SYN Flood Tespiti
        syn_threshold = getattr(Ayarlar, "SYN_FLOOD_THRESHOLD", 100)
        for ip, syn_count in self.syn_counts.items():
            if syn_count > syn_threshold:
                anomalies.append(
                    {
                        "type": "SYN_FLOOD_DDOS",
                        "source_ip": ip,
                        "details": (
                            f"{syn_count} adet sadece SYN paketi (ACK beklenmeyen) gönderildi."
                        ),
                    }
                )

        # 4. Data Exfiltration Tespiti
        for src, dst, length in self.large_transfers:
            anomalies.append(
                {
                    "type": "DATA_EXFILTRATION",
                    "source_ip": src,
                    "details": f"Aşırı büyük payload aktarımı ({length} byte) Hedef: {dst}",
                }
            )

        # 5. HTTP DPI Tespiti
        for ip, payload in self.suspicious_http:
            anomalies.append(
                {
                    "type": "HTTP_MALICIOUS_PAYLOAD",
                    "source_ip": ip,
                    "details": f"HTTP paketinde şüpheli veri tespit edildi: {payload[:50]}...",
                }
            )

        return anomalies
