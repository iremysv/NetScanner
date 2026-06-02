# -*- coding: utf-8 -*-
"""
modules/vuln_scanner/full_scanner.py

Full Vulnerability Scanner — Otomatik Tarama Zinciri:

  AŞAMA 1: Nmap ile port keşfi ve servis tespiti (vize modülü)
  AŞAMA 2: NSE vuln scriptleriyle zafiyet taraması (vize modülü)
  AŞAMA 3: PCAP / canlı trafik analizi (vize modülü — TrafficAnalyzer)
  AŞAMA 4: API güvenlik taraması (yeni modül — APISecurityScanner)
  AŞAMA 5: Credential testi (yeni modül — CredentialTester)
  AŞAMA 6: Birleşik Markdown raporu oluştur

Bu sınıf sadece mevcut modülleri sırayla çağırır ve
sonuçları tek bir raporda birleştirir. Bağımsız hata yönetimi sayesinde
bir aşama başarısız olursa diğerleri çalışmaya devam eder.
"""

import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from modules.nmap_integration.scanner import nmap_calistir
from modules.nmap_integration.vulnerability import zafiyet_tara
from modules.nmap_integration.analyzer import analiz_et
from modules.packet_engine.pcap_reader import PcapReader
from modules.packet_engine.traffic_analyzer import TrafficAnalyzer
from modules.api_scanner.scanner import APISecurityScanner, APISecurityReport
from modules.credential_tester.tester import (
    CredentialTester,
    CredentialTestReport,
)
from reports.markdown_reporter import markdown_guvenlik_raporu_olustur
from core import config as Ayarlar

logger = logging.getLogger("FullVulnerabilityScanner")


# -------------------------------------------------------------------------
# Aşama Sonuç Nesnesi
# -------------------------------------------------------------------------

@dataclass
class ScanPhaseResult:
    """Tek bir tarama aşamasının sonucu."""
    name: str
    success: bool
    data: dict = field(default_factory=dict)
    error: str = ""
    duration_seconds: float = 0.0


@dataclass
class FullScanReport:
    """Full Vulnerability Scanner birleşik raporu."""
    target: str
    started_at: str = ""
    finished_at: str = ""
    phases: list[ScanPhaseResult] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    nmap_vuln_output: str = ""
    traffic_analysis: Optional[dict] = None
    api_report: Optional[APISecurityReport] = None
    credential_report: Optional[CredentialTestReport] = None
    overall_risk: str = "Bilinmiyor"
    report_path: str = ""


# -------------------------------------------------------------------------
# Ana Sınıf
# -------------------------------------------------------------------------

class FullVulnerabilityScanner:
    """
    Tüm NetScanner modüllerini sırayla çalıştıran otomatik tarama zinciri.

    Kullanım:
        scanner = FullVulnerabilityScanner(
            target="192.168.1.1",
            pcap_file="trafik.pcap",        # opsiyonel
            api_base_url="http://hedef/api", # opsiyonel
            login_url="http://hedef/login",  # opsiyonel
        )
        rapor = scanner.run_full_scan()
    """

    def __init__(
        self,
        target: str,
        pcap_file: Optional[str] = None,
        api_base_url: Optional[str] = None,
        login_url: Optional[str] = None,
        openapi_url: Optional[str] = None,
        skip_phases: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            target: Hedef IP adresi veya domain
            pcap_file: Analiz edilecek .pcap dosyası yolu (opsiyonel)
            api_base_url: API güvenlik taraması için base URL (opsiyonel)
            login_url: Credential testi için login endpoint URL'si (opsiyonel)
            openapi_url: OpenAPI/Swagger spec URL'si (opsiyonel)
            skip_phases: Atlanacak aşama isimleri listesi (opsiyonel)
        """
        self.target = target
        self.pcap_file = pcap_file
        self.api_base_url = api_base_url or f"http://{target}"
        self.login_url = login_url
        self.openapi_url = openapi_url
        self.skip_phases = set(skip_phases or [])
        self._hiz = Ayarlar.TARAMA_HIZI

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_full_scan(self) -> FullScanReport:
        """
        Tüm tarama aşamalarını sırayla çalıştırır.
        Her aşamayı bağımsız try/except ile sararak zincirin kırılmasını önler.

        Returns:
            FullScanReport nesnesi
        """
        report = FullScanReport(
            target=self.target,
            started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        print(f"\n{'='*60}")
        print(f"  FULL VULNERABILITY SCANNER — Hedef: {self.target}")
        print(f"{'='*60}\n")

        # ──────────────────────────────────────────────────────────────
        # AŞAMA 1: Nmap Port Keşfi
        # ──────────────────────────────────────────────────────────────
        if "nmap_quick" not in self.skip_phases:
            phase = self._run_phase(
                "Nmap Port Keşfi",
                self._phase_nmap_quick,
                report,
            )
            report.phases.append(phase)
            if phase.success:
                report.open_ports = phase.data.get("open_ports", [])

        # ──────────────────────────────────────────────────────────────
        # AŞAMA 2: Nmap Servis & Zafiyet Taraması
        # ──────────────────────────────────────────────────────────────
        if "nmap_vuln" not in self.skip_phases:
            phase = self._run_phase(
                "Nmap Zafiyet Taraması",
                self._phase_nmap_vuln,
                report,
            )
            report.phases.append(phase)
            if phase.success:
                report.nmap_vuln_output = phase.data.get("vuln_output", "")

        # ──────────────────────────────────────────────────────────────
        # AŞAMA 3: Trafik Analizi (PCAP veya live)
        # ──────────────────────────────────────────────────────────────
        if "traffic" not in self.skip_phases:
            phase = self._run_phase(
                "Trafik Analizi",
                self._phase_traffic_analysis,
                report,
            )
            report.phases.append(phase)
            if phase.success:
                report.traffic_analysis = phase.data.get("results")

        # ──────────────────────────────────────────────────────────────
        # AŞAMA 4: API Güvenlik Taraması
        # ──────────────────────────────────────────────────────────────
        if "api_scan" not in self.skip_phases:
            phase = self._run_phase(
                "API Güvenlik Taraması",
                self._phase_api_scan,
                report,
            )
            report.phases.append(phase)
            if phase.success:
                report.api_report = phase.data.get("api_report")

        # ──────────────────────────────────────────────────────────────
        # AŞAMA 5: Credential Testi
        # ──────────────────────────────────────────────────────────────
        if "credential" not in self.skip_phases and self.login_url:
            phase = self._run_phase(
                "Credential Testi",
                self._phase_credential_test,
                report,
            )
            report.phases.append(phase)
            if phase.success:
                report.credential_report = phase.data.get("credential_report")

        # ──────────────────────────────────────────────────────────────
        # AŞAMA 6: Birleşik Rapor Oluştur
        # ──────────────────────────────────────────────────────────────
        report.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report.overall_risk = self._evaluate_overall_risk(report)
        report.report_path = self._generate_combined_report(report)

        # Özet ekrana yazdır
        self._print_summary(report)
        return report

    # ------------------------------------------------------------------
    # Aşama İmplementasyonları
    # ------------------------------------------------------------------

    def _phase_nmap_quick(self, report: FullScanReport) -> ScanPhaseResult:
        """Hızlı Nmap port taraması ve servis tespiti."""
        print("[AŞAMA 1] Nmap hızlı port taraması...")
        komut = ["nmap", self._hiz, "-sV", "-F", self.target]
        stdout, _ = nmap_calistir(komut, self.target, "full_scan_quick")
        if not stdout:
            return ScanPhaseResult(
                name="Nmap Port Keşfi",
                success=False,
                error="nmap çalıştırılamadı veya hedef yanıt vermedi.",
            )

        open_ports = re.findall(r"(\d+)/tcp\s+open", stdout)
        analiz_et(open_ports)

        return ScanPhaseResult(
            name="Nmap Port Keşfi",
            success=True,
            data={
                "open_ports": open_ports,
                "nmap_output": stdout,
            },
        )

    def _phase_nmap_vuln(self, report: FullScanReport) -> ScanPhaseResult:
        """NSE vuln scriptleriyle derinlemesine zafiyet taraması."""
        print("[AŞAMA 2] Nmap zafiyet taraması (NSE --script=vuln)...")
        vuln_output = zafiyet_tara(self.target)
        if "hata" in vuln_output.lower():
            return ScanPhaseResult(
                name="Nmap Zafiyet Taraması",
                success=False,
                error=vuln_output[:200],
            )
        return ScanPhaseResult(
            name="Nmap Zafiyet Taraması",
            success=True,
            data={"vuln_output": vuln_output},
        )

    def _phase_traffic_analysis(
        self, report: FullScanReport
    ) -> ScanPhaseResult:
        """PCAP dosyasından trafik analizi ve anomali tespiti."""
        print("[AŞAMA 3] Trafik analizi başlatılıyor...")

        if self.pcap_file and os.path.exists(self.pcap_file):
            reader = PcapReader(self.pcap_file)
            if not reader.read_pcap():
                return ScanPhaseResult(
                    name="Trafik Analizi",
                    success=False,
                    error=f"PCAP dosyası okunamadı: {self.pcap_file}",
                )
            packets = reader.parse_packets()
        else:
            if self.pcap_file:
                logger.warning(
                    f"PCAP dosyası bulunamadı: {self.pcap_file}. "
                    "Trafik analizi atlanıyor."
                )
            return ScanPhaseResult(
                name="Trafik Analizi",
                success=False,
                error="PCAP dosyası belirtilmedi veya bulunamadı.",
            )

        analyzer = TrafficAnalyzer(packets)
        results = analyzer.analyze()
        return ScanPhaseResult(
            name="Trafik Analizi",
            success=True,
            data={"results": results},
        )

    def _phase_api_scan(self, report: FullScanReport) -> ScanPhaseResult:
        """API güvenlik taraması — OWASP API Top 10."""
        print(f"[AŞAMA 4] API güvenlik taraması → {self.api_base_url}...")
        try:
            api_scanner = APISecurityScanner(
                base_url=self.api_base_url,
                timeout=6,
                delay=0.3,
            )
            api_report = api_scanner.scan(openapi_url=self.openapi_url)
            return ScanPhaseResult(
                name="API Güvenlik Taraması",
                success=True,
                data={"api_report": api_report},
            )
        except Exception as e:
            return ScanPhaseResult(
                name="API Güvenlik Taraması",
                success=False,
                error=str(e),
            )

    def _phase_credential_test(
        self, report: FullScanReport
    ) -> ScanPhaseResult:
        """Rate limiting, parola politikası ve lockout testleri."""
        if not self.login_url:
            return ScanPhaseResult(
                name="Credential Testi",
                success=False,
                error="login_url belirtilmedi.",
            )

        print(f"[AŞAMA 5] Credential testi → {self.login_url}...")
        try:
            tester = CredentialTester(
                target_url=self.login_url,
                delay_between_requests=0.3,
            )
            cred_report = tester.run_all_tests(max_rate_requests=15)
            return ScanPhaseResult(
                name="Credential Testi",
                success=True,
                data={"credential_report": cred_report},
            )
        except Exception as e:
            return ScanPhaseResult(
                name="Credential Testi",
                success=False,
                error=str(e),
            )

    # ------------------------------------------------------------------
    # Yardımcı Metotlar
    # ------------------------------------------------------------------

    def _run_phase(
        self,
        name: str,
        func,
        report: FullScanReport,
    ) -> ScanPhaseResult:
        """Bir aşamayı çalıştırır, süreyi ölçer ve hataları yakalar."""
        start = time.time()
        try:
            result = func(report)
            result.duration_seconds = round(time.time() - start, 2)
            return result
        except Exception as e:
            logger.error(f"Aşama hatası [{name}]: {e}")
            return ScanPhaseResult(
                name=name,
                success=False,
                error=str(e),
                duration_seconds=round(time.time() - start, 2),
            )

    def _evaluate_overall_risk(self, report: FullScanReport) -> str:
        """Tüm aşamaların bulgularına göre genel risk belirler."""
        risk_score = 0

        # Açık port sayısı
        risk_score += min(len(report.open_ports) * 5, 30)

        # NSE zafiyet çıktısı — exploit/vuln varsa ciddi risk
        if report.nmap_vuln_output:
            vuln_lower = report.nmap_vuln_output.lower()
            if "vuln" in vuln_lower or "exploit" in vuln_lower:
                risk_score += 40   # Kritik zafiyet işareti

        # Trafik anomalileri
        if report.traffic_analysis:
            anomalies = report.traffic_analysis.get("anomalies", [])
            for a in anomalies:
                if a.get("type") in ("SYN_FLOOD_DDOS", "DATA_EXFILTRATION"):
                    risk_score += 30   # Her kritik anomali +30
                elif a.get("type") in ("PORT_SCAN", "DNS_TUNNELING_SUSPICION"):
                    risk_score += 15

        # API bulgular
        if report.api_report:
            for finding in report.api_report.findings:
                if finding.severity == "Kritik":
                    risk_score += 20
                elif finding.severity == "Yüksek":
                    risk_score += 10

        # Credential bulgular
        if report.credential_report:
            cred = report.credential_report
            if cred.lockout and not cred.lockout.lockout_detected:
                risk_score += 20
            if cred.rate_limit and not cred.rate_limit.detected:
                risk_score += 10

        if risk_score >= 60:
            return "Kritik"
        elif risk_score >= 40:
            return "Yüksek"
        elif risk_score >= 20:
            return "Orta"
        return "Düşük"

    def _generate_combined_report(self, report: FullScanReport) -> str:
        """Birleşik Markdown raporu oluşturur."""
        # Trafik anomalilerini trafik_sonuclar formatında aktar
        trafik_sonuclar = report.traffic_analysis

        # API bulgularını nmap_ciktisi tarzında ekle
        nmap_ek = report.nmap_vuln_output or ""
        if report.api_report:
            nmap_ek += "\n\n=== API GÜVENLİK BULGULARI ===\n"
            for f in report.api_report.findings:
                nmap_ek += (
                    f"[{f.owasp_id}] {f.severity} — {f.endpoint}: "
                    f"{f.description}\n"
                )

        # Credential raporunu da ekle
        if report.credential_report:
            nmap_ek += "\n\n=== CREDENTIAL TEST BULGULARI ===\n"
            nmap_ek += report.credential_report.summary

        connection_map = None
        if trafik_sonuclar:
            connection_map = trafik_sonuclar.get("connection_map")

        rapor_yolu = markdown_guvenlik_raporu_olustur(
            hedef=self.target,
            trafik_sonuclar=trafik_sonuclar,
            acik_portlar=report.open_ports,
            nmap_ciktisi=nmap_ek,
            connection_map=connection_map,
        )
        return rapor_yolu

    def _print_summary(self, report: FullScanReport) -> None:
        """Konsola özet tablo yazdırır."""
        print(f"\n{'='*60}")
        print(f"  FULL SCAN TAMAMLANDI — {report.finished_at}")
        print(f"{'='*60}")
        for phase in report.phases:
            status = "✅" if phase.success else "❌"
            print(
                f"  {status} {phase.name:<35} "
                f"[{phase.duration_seconds:.1f}s]"
            )
            if not phase.success and phase.error:
                print(f"     └─ Hata: {phase.error[:80]}")

        print(f"\n  Açık Port Sayısı : {len(report.open_ports)}")
        if report.open_ports:
            print(f"  Açık Portlar     : {', '.join(report.open_ports[:10])}")
        print(f"  Genel Risk       : {report.overall_risk}")
        if report.report_path:
            print(f"  Rapor Dosyası    : {report.report_path}")
        print(f"{'='*60}\n")
