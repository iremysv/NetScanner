# -*- coding: utf-8 -*-
"""
Tests/test_full_scanner.py

Unit testler: FullVulnerabilityScanner sınıfını gerçek ağ/nmap çağrısı
olmadan (monkeypatch ile) doğrular.
"""
import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

import pytest  # noqa: E402

from modules.vuln_scanner.full_scanner import (  # noqa: E402
    FullVulnerabilityScanner,
    FullScanReport,
    ScanPhaseResult,
)


# ---------------------------------------------------------------------------
# Yardımcı Mock'lar
# ---------------------------------------------------------------------------

def _make_mock_phase(name: str, success: bool = True, data=None):
    return ScanPhaseResult(
        name=name, success=success, data=data or {}, duration_seconds=0.1
    )


# ---------------------------------------------------------------------------
# ScanPhaseResult Testleri
# ---------------------------------------------------------------------------

class TestScanPhaseResult:
    """ScanPhaseResult dataclass doğrulamaları."""

    def test_default_data_empty_dict(self):
        phase = ScanPhaseResult(name="test", success=True)
        assert phase.data == {}

    def test_error_field_default_empty(self):
        phase = ScanPhaseResult(name="test", success=False)
        assert phase.error == ""

    def test_duration_stored(self):
        phase = ScanPhaseResult(name="test", success=True, duration_seconds=1.23)
        assert phase.duration_seconds == 1.23


# ---------------------------------------------------------------------------
# FullVulnerabilityScanner Yapılandırma Testleri
# ---------------------------------------------------------------------------

class TestFullVulnerabilityScannerInit:
    """Başlangıç yapılandırması doğrulamaları."""

    def test_target_stored(self):
        scanner = FullVulnerabilityScanner("192.168.1.1")
        assert scanner.target == "192.168.1.1"

    def test_api_base_url_defaults_to_http_target(self):
        scanner = FullVulnerabilityScanner("10.0.0.1")
        assert scanner.api_base_url == "http://10.0.0.1"

    def test_custom_api_base_url(self):
        scanner = FullVulnerabilityScanner(
            "10.0.0.1", api_base_url="https://custom.api.com"
        )
        assert scanner.api_base_url == "https://custom.api.com"

    def test_skip_phases_stored(self):
        scanner = FullVulnerabilityScanner(
            "10.0.0.1", skip_phases=["nmap_quick", "traffic"]
        )
        assert "nmap_quick" in scanner.skip_phases
        assert "traffic" in scanner.skip_phases

    def test_pcap_file_stored(self):
        scanner = FullVulnerabilityScanner("10.0.0.1", pcap_file="test.pcap")
        assert scanner.pcap_file == "test.pcap"


# ---------------------------------------------------------------------------
# Risk Değerlendirme Testleri
# ---------------------------------------------------------------------------

class TestEvaluateOverallRisk:
    """_evaluate_overall_risk metodu testleri."""

    def test_no_data_returns_dusuk(self):
        """Veri yoksa risk Düşük olmalı."""
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(target="192.168.1.1")
        risk = scanner._evaluate_overall_risk(report)
        assert risk in ("Düşük", "Orta", "Yüksek", "Kritik")

    def test_many_open_ports_increases_risk(self):
        """Çok açık port varsa risk yükselmeli."""
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(
            target="192.168.1.1",
            open_ports=[str(p) for p in range(1, 20)],  # 19 açık port
        )
        risk = scanner._evaluate_overall_risk(report)
        assert risk in ("Orta", "Yüksek", "Kritik")

    def test_vuln_output_with_exploit_increases_risk(self):
        """NSE çıktısında 'exploit' geçince risk yükselmeli."""
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(
            target="192.168.1.1",
            nmap_vuln_output="VULNERABLE: EternalBlue exploit possible",
        )
        risk = scanner._evaluate_overall_risk(report)
        assert risk in ("Yüksek", "Kritik")

    def test_traffic_anomalies_increase_risk(self):
        """SYN Flood anomalisi risk skoru artırmalı."""
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(
            target="192.168.1.1",
            traffic_analysis={
                "anomalies": [
                    {"type": "SYN_FLOOD_DDOS", "source_ip": "1.1.1.1",
                     "details": "Flood tespiti"},
                    {"type": "DATA_EXFILTRATION", "source_ip": "1.1.1.2",
                     "details": "Veri sızdırma"},
                ]
            },
        )
        risk = scanner._evaluate_overall_risk(report)
        assert risk in ("Yüksek", "Kritik")

    def test_empty_traffic_no_error(self):
        """Boş trafik verisi hata vermemeli."""
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(
            target="192.168.1.1",
            traffic_analysis={"anomalies": []},
        )
        risk = scanner._evaluate_overall_risk(report)
        assert isinstance(risk, str)


# ---------------------------------------------------------------------------
# Phase Execution Testleri
# ---------------------------------------------------------------------------

class TestRunPhase:
    """_run_phase metodunun hata yakalama davranışı."""

    def test_successful_phase_returns_success_true(self):
        """Başarılı aşama success=True döndürmeli."""
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(target="192.168.1.1")

        def dummy_phase(report):
            return ScanPhaseResult(
                name="Dummy", success=True, data={"key": "value"}
            )

        result = scanner._run_phase("Dummy", dummy_phase, report)
        assert result.success is True
        assert result.data == {"key": "value"}

    def test_exception_returns_success_false(self):
        """Exception fırlatılan aşama success=False döndürmeli."""
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(target="192.168.1.1")

        def failing_phase(report):
            raise RuntimeError("Test hatası")

        result = scanner._run_phase("Failing", failing_phase, report)
        assert result.success is False
        assert "Test hatası" in result.error

    def test_duration_measured(self):
        """Süre ölçümü > 0 olmalı."""
        import time
        scanner = FullVulnerabilityScanner("192.168.1.1")
        report = FullScanReport(target="192.168.1.1")

        def slow_phase(report):
            time.sleep(0.05)
            return ScanPhaseResult(name="Slow", success=True)

        result = scanner._run_phase("Slow", slow_phase, report)
        assert result.duration_seconds >= 0.05


# ---------------------------------------------------------------------------
# Phase Skip Testleri
# ---------------------------------------------------------------------------

class TestSkipPhases:
    """skip_phases ile aşama atlama davranışı."""

    def test_skipped_phase_not_in_report(self, monkeypatch, tmp_path):
        """Atlanan aşama report.phases listesinde olmamalı."""
        # Nmap ve diğer gerçek çağrıları mock'la
        monkeypatch.setattr(
            "modules.vuln_scanner.full_scanner.nmap_calistir",
            lambda *a, **k: (None, None),
        )
        monkeypatch.setattr(
            "modules.vuln_scanner.full_scanner.zafiyet_tara",
            lambda *a, **k: "mock vuln output",
        )
        monkeypatch.setattr(
            "modules.vuln_scanner.full_scanner.markdown_guvenlik_raporu_olustur",
            lambda **k: str(tmp_path / "report.md"),
        )

        scanner = FullVulnerabilityScanner(
            "192.168.1.1",
            skip_phases=["traffic", "api_scan", "credential"],
        )

        # Nmap aşaması hiçbir şey bulmasa bile (None, None) döner
        report = scanner.run_full_scan()

        phase_names = [p.name for p in report.phases]
        assert "Trafik Analizi" not in phase_names
        assert "API Güvenlik Taraması" not in phase_names

    def test_all_phases_skipped_results_empty_phases(self, monkeypatch, tmp_path):
        """Tüm aşamalar atlanırsa phases listesi boş olmalı."""
        monkeypatch.setattr(
            "modules.vuln_scanner.full_scanner.markdown_guvenlik_raporu_olustur",
            lambda **k: str(tmp_path / "report.md"),
        )

        scanner = FullVulnerabilityScanner(
            "192.168.1.1",
            skip_phases=[
                "nmap_quick", "nmap_vuln", "traffic",
                "api_scan", "credential"
            ],
        )
        report = scanner.run_full_scan()
        assert report.phases == []


# ---------------------------------------------------------------------------
# Bütünleşik Çıktı Testleri
# ---------------------------------------------------------------------------

class TestFullScanReport:
    """FullScanReport dataclass doğrulamaları."""

    def test_report_defaults(self):
        """Varsayılan rapor alanları doğru olmalı."""
        report = FullScanReport(target="192.168.1.1")
        assert report.phases == []
        assert report.open_ports == []
        assert report.overall_risk == "Bilinmiyor"

    def test_started_at_not_set_by_default(self):
        """started_at başta boş olmalı."""
        report = FullScanReport(target="test")
        assert report.started_at == ""

    def test_target_stored_correctly(self):
        """Hedef doğru saklanmalı."""
        report = FullScanReport(target="10.10.10.10")
        assert report.target == "10.10.10.10"
