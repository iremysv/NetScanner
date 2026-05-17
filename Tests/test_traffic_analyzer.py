# -*- coding: utf-8 -*-
"""
Tests/test_traffic_analyzer.py
Unit testler: TrafficAnalyzer sınıfının analiz ve anomali tespit mantığını
gerçek ağ bağlantısı gerektirmeden (GeoIP mock'lanarak) doğrular.
"""
import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

import pytest  # noqa: E402
from modules.packet_engine.traffic_analyzer import (  # noqa: E402
    TrafficAnalyzer,
)


# --------------------------------------------------------------------------- #
# Yardımcı: Sahte paket üreticisi                                             #
# --------------------------------------------------------------------------- #

def _make_packet(
    src_ip: str,
    dst_ip: str = "8.8.8.8",
    dst_port: int = 80,
    protocol: str = "TCP",
    flags: str = "",
    length: int = 100,
    payload_preview: str = None,
    dns_query: str = None,
) -> dict:
    """TrafficAnalyzer'ın beklediği dict formatında sahte paket oluşturur."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 12345,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "flags": flags,
        "payload_preview": payload_preview,
        "dns_query": dns_query,
    }


# GeoIP dış API çağrısını tüm testlerde otomatik mock'la
@pytest.fixture(autouse=True)
def mock_geoip(monkeypatch):
    """ip-api.com çağrısını engelle;
    tüm IP'ler için 'Yerel Ağ (Local)' döndür."""
    monkeypatch.setattr(
        "modules.packet_engine.traffic_analyzer"
        ".TrafficAnalyzer._get_geoip",
        lambda self, ip: "Yerel Ağ (Local)",
    )


# --------------------------------------------------------------------------- #
# Test Sınıfları                                                               #
# --------------------------------------------------------------------------- #

class TestTrafficAnalyzerBasic:
    """Temel analiz çıktısını doğrulayan testler."""

    def test_empty_packets_returns_empty_dict(self):
        """Paket listesi boşsa analyze() boş dict döndürmeli."""
        analyzer = TrafficAnalyzer([])
        result = analyzer.analyze()
        assert result == {}, f"Beklenen {{}}, alınan: {result}"

    def test_analyze_returns_required_keys(self):
        """analyze() çıktısı zorunlu anahtarları içermeli."""
        packets = [_make_packet("192.168.1.1")]
        analyzer = TrafficAnalyzer(packets)
        result = analyzer.analyze()

        for key in (
            "total_packets", "top_talkers",
            "protocol_distribution", "anomalies",
        ):
            assert key in result, f"Eksik anahtar: {key}"

    def test_total_packets_count(self):
        """total_packets, verilen paket sayısıyla eşleşmeli."""
        packets = [_make_packet("10.0.0.1") for _ in range(25)]
        result = TrafficAnalyzer(packets).analyze()
        assert result["total_packets"] == 25

    def test_protocol_distribution_counted(self):
        """Protokol dağılımı doğru sayılmalı."""
        packets = (
            [_make_packet("10.0.0.1", protocol="HTTP")] * 5
            + [_make_packet("10.0.0.2", protocol="DNS")] * 3
        )
        result = TrafficAnalyzer(packets).analyze()
        dist = result["protocol_distribution"]
        assert dist.get("HTTP") == 5, (
            f"HTTP sayısı 5 olmalı, alınan: {dist.get('HTTP')}"
        )
        assert dist.get("DNS") == 3, (
            f"DNS sayısı 3 olmalı, alınan: {dist.get('DNS')}"
        )

    def test_top_talkers_structure(self):
        """top_talkers listesi dict'lerden oluşmalı;
        ip/count/location içermeli."""
        packets = [_make_packet("192.168.1.100") for _ in range(5)]
        result = TrafficAnalyzer(packets).analyze()
        talkers = result["top_talkers"]
        assert isinstance(talkers, list)
        assert len(talkers) > 0
        for t in talkers:
            for field in ("ip", "count", "location"):
                assert field in t, (
                    f"top_talkers dict'inde eksik alan: {field}"
                )


class TestAnomalyDetection:
    """Anomali tespiti mantığını doğrulayan testler."""

    def test_no_anomaly_on_normal_traffic(self):
        """Normal trafik → anomali listesi boş olmalı."""
        packets = [_make_packet("10.0.0.1", dst_port=80, protocol="HTTP")]
        result = TrafficAnalyzer(packets).analyze()
        assert result["anomalies"] == [], (
            f"Normal trafik için anomali beklenmez, "
            f"alınan: {result['anomalies']}"
        )

    def test_port_scan_detected(self):
        """
        Bir IP'den PORT_SCAN_THRESHOLD'u aşan sayıda farklı porta
        bağlantı denemesi → PORT_SCAN anomalisi tespit edilmeli.
        """
        from core import config as Ayarlar

        threshold = Ayarlar.PORT_SCAN_THRESHOLD
        # Eşiği 2 fazla port ile aş
        packets = [
            _make_packet("192.168.1.50", dst_port=port, protocol="TCP")
            for port in range(1, threshold + 3)
        ]
        result = TrafficAnalyzer(packets).analyze()
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "PORT_SCAN" in anomaly_types, (
            f"PORT_SCAN beklendi fakat bulunamadı. "
            f"Anomaliler: {anomaly_types}"
        )

    def test_port_scan_source_ip_correct(self):
        """PORT_SCAN anomalisinde kaynak IP doğru raporlanmalı."""
        from core import config as Ayarlar

        threshold = Ayarlar.PORT_SCAN_THRESHOLD
        attacker_ip = "172.16.0.99"
        packets = [
            _make_packet(attacker_ip, dst_port=p, protocol="TCP")
            for p in range(1, threshold + 3)
        ]
        result = TrafficAnalyzer(packets).analyze()
        port_scan_anomalies = [
            a for a in result["anomalies"] if a["type"] == "PORT_SCAN"
        ]
        assert any(
            a["source_ip"] == attacker_ip for a in port_scan_anomalies
        ), (
            f"Saldırgan IP {attacker_ip} raporlanmadı. "
            f"Anomaliler: {port_scan_anomalies}"
        )

    def test_dns_tunneling_detected(self):
        """
        Bir IP'den DNS_TUNNELING_THRESHOLD'u aşan sayıda DNS isteği
        → DNS_TUNNELING_SUSPICION anomalisi tespit edilmeli.
        """
        from core import config as Ayarlar

        threshold = Ayarlar.DNS_TUNNELING_THRESHOLD
        packets = [
            _make_packet("10.10.10.10", protocol="DNS", dst_port=53)
            for _ in range(threshold + 5)
        ]
        result = TrafficAnalyzer(packets).analyze()
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "DNS_TUNNELING_SUSPICION" in anomaly_types, (
            f"DNS_TUNNELING_SUSPICION beklendi. Anomaliler: {anomaly_types}"
        )

    def test_syn_flood_detected(self):
        """
        Bir IP'den SYN_FLOOD_THRESHOLD'u aşan sayıda saf SYN paketi
        → SYN_FLOOD_DDOS anomalisi tespit edilmeli.
        """
        from core import config as Ayarlar

        threshold = Ayarlar.SYN_FLOOD_THRESHOLD
        # flags="S" → sadece SYN, ACK yok
        packets = [
            _make_packet("203.0.113.5", protocol="TCP", flags="S")
            for _ in range(threshold + 10)
        ]
        result = TrafficAnalyzer(packets).analyze()
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "SYN_FLOOD_DDOS" in anomaly_types, (
            f"SYN_FLOOD_DDOS beklendi. Anomaliler: {anomaly_types}"
        )

    def test_data_exfiltration_detected(self):
        """
        LARGE_PAYLOAD_THRESHOLD'u aşan paket boyutu
        → DATA_EXFILTRATION anomalisi tespit edilmeli.
        """
        from core import config as Ayarlar

        big_size = Ayarlar.LARGE_PAYLOAD_THRESHOLD + 1
        packets = [_make_packet("10.0.0.5", length=big_size)]
        result = TrafficAnalyzer(packets).analyze()
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "DATA_EXFILTRATION" in anomaly_types, (
            f"DATA_EXFILTRATION beklendi. Anomaliler: {anomaly_types}"
        )

    def test_http_malicious_payload_detected(self):
        """
        HTTP paketinde SQL/XSS içeren payload
        → HTTP_MALICIOUS_PAYLOAD anomalisi.
        """
        packets = [
            _make_packet(
                "10.0.1.1",
                protocol="HTTP",
                payload_preview="GET /?sql=1' OR 1=1-- HTTP/1.1",
            )
        ]
        result = TrafficAnalyzer(packets).analyze()
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "HTTP_MALICIOUS_PAYLOAD" in anomaly_types, (
            f"HTTP_MALICIOUS_PAYLOAD beklendi. Anomaliler: {anomaly_types}"
        )

    def test_multiple_anomalies_from_same_ip(self):
        """Aynı IP hem port scan hem SYN flood yapabilmeli
        → her iki anomali de listede."""
        from core import config as Ayarlar

        ip = "198.51.100.1"
        # Port scan
        port_packets = [
            _make_packet(ip, dst_port=p, protocol="TCP", flags="S")
            for p in range(1, Ayarlar.PORT_SCAN_THRESHOLD + 5)
        ]
        # SYN flood (aynı porttan çok sayıda SYN)
        syn_packets = [
            _make_packet(ip, dst_port=80, protocol="TCP", flags="S")
            for _ in range(Ayarlar.SYN_FLOOD_THRESHOLD + 5)
        ]
        result = TrafficAnalyzer(port_packets + syn_packets).analyze()
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert "PORT_SCAN" in anomaly_types
        assert "SYN_FLOOD_DDOS" in anomaly_types
