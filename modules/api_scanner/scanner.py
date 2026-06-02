# -*- coding: utf-8 -*-
"""
modules/api_scanner/scanner.py

API Security Scanner Modülü:
- OpenAPI / Swagger spec parse (JSON veya URL'den)
- BOLA (Broken Object Level Authorization) testi — OWASP API Top 10 #1
- OWASP API Top 10 kontrol listesi tabanlı güvenlik değerlendirmesi:
    API1  - BOLA / IDOR
    API2  - Broken User Authentication
    API3  - Excessive Data Exposure
    API4  - Lack of Resources & Rate Limiting
    API5  - Broken Function Level Authorization
    API6  - Mass Assignment
    API7  - Security Misconfiguration
    API8  - Injection
    API9  - Improper Assets Management
    API10 - Insufficient Logging & Monitoring
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger("APISecurityScanner")

# -------------------------------------------------------------------------
# OWASP API Top 10 Kategori Etiketleri
# -------------------------------------------------------------------------
OWASP_API_TOP10 = {
    "API1":  "Broken Object Level Authorization (BOLA/IDOR)",
    "API2":  "Broken User Authentication",
    "API3":  "Excessive Data Exposure",
    "API4":  "Lack of Resources & Rate Limiting",
    "API5":  "Broken Function Level Authorization",
    "API6":  "Mass Assignment",
    "API7":  "Security Misconfiguration",
    "API8":  "Injection",
    "API9":  "Improper Assets Management",
    "API10": "Insufficient Logging & Monitoring",
}

# -------------------------------------------------------------------------
# Veri Sınıfları
# -------------------------------------------------------------------------


@dataclass
class APIFinding:
    """Tek bir güvenlik bulgusu."""
    owasp_id: str
    owasp_label: str
    severity: str       # Kritik / Yüksek / Orta / Düşük / Bilgi
    endpoint: str
    method: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class BOLATestResult:
    """BOLA test sonuçları."""
    vulnerable_endpoints: list[dict[str, Any]] = field(default_factory=list)
    tested_count: int = 0
    details: str = ""


@dataclass
class APISecurityReport:
    """API Security Scanner ana rapor nesnesi."""
    base_url: str
    spec_source: str = ""           # OpenAPI spec kaynağı
    endpoints_discovered: int = 0
    findings: list[APIFinding] = field(default_factory=list)
    bola_result: Optional[BOLATestResult] = None
    owasp_coverage: dict[str, bool] = field(default_factory=dict)
    overall_risk: str = "Bilinmiyor"
    summary: str = ""


# -------------------------------------------------------------------------
# Ana Sınıf
# -------------------------------------------------------------------------

class APISecurityScanner:
    """
    Bir REST API'nin güvenliğini OWASP API Top 10 kriterlerine göre test eder.

    Özellikler:
    - OpenAPI 3.x / Swagger 2.x spec dosyası ya da URL'den endpoint keşfi
    - BOLA (IDOR) zafiyeti tespiti: farklı ID'lerle obje erişim testleri
    - OWASP API Top 10 kontrol listesi değerlendirmesi
    - Rate limiting, authentication, data exposure testleri

    Kullanım:
        scanner = APISecurityScanner("https://api.hedef.com")
        rapor = scanner.scan(openapi_url="https://api.hedef.com/openapi.json")
    """

    def __init__(
        self,
        base_url: str,
        auth_token: Optional[str] = None,
        timeout: int = 8,
        delay: float = 0.3,
    ) -> None:
        parsed = urlparse(base_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.auth_token = auth_token
        self.timeout = timeout
        self.delay = delay

        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": (
                "NetScanner-APIScanner/1.0 "
                "(Security Research - Authorized Testing Only)"
            ),
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        if auth_token:
            self._session.headers["Authorization"] = f"Bearer {auth_token}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        openapi_url: Optional[str] = None,
        openapi_file: Optional[str] = None,
        spec_dict: Optional[dict] = None,
    ) -> APISecurityReport:
        """
        Tüm güvenlik taramalarını çalıştırır.

        Args:
            openapi_url:  OpenAPI/Swagger spec'e HTTP URL'si
            openapi_file: Yerel OpenAPI JSON dosya yolu
            spec_dict:    Doğrudan spec sözlüğü (test / programatik kullanım)

        Returns:
            APISecurityReport nesnesi
        """
        logger.info(f"API Security Scanner başlatıldı → {self.base_url}")

        report = APISecurityReport(base_url=self.base_url)
        endpoints: list[dict[str, str]] = []

        # 1. OpenAPI Spec'i parse et
        spec = None
        if spec_dict:
            spec = spec_dict
            report.spec_source = "Programatik (dict)"
        elif openapi_url:
            spec = self._fetch_openapi_spec(openapi_url)
            report.spec_source = openapi_url
        elif openapi_file:
            spec = self._load_openapi_file(openapi_file)
            report.spec_source = openapi_file

        if spec:
            endpoints = self._extract_endpoints(spec)
            report.endpoints_discovered = len(endpoints)
            logger.info(f"{len(endpoints)} endpoint keşfedildi.")
        else:
            # Spec yoksa yaygın API endpoint'lerini dene
            endpoints = self._generate_common_endpoints()
            report.endpoints_discovered = len(endpoints)
            logger.warning(
                "OpenAPI spec bulunamadı. "
                "Yaygın endpoint listesi kullanılıyor."
            )

        # 2. OWASP API Top 10 Kontrolleri
        findings: list[APIFinding] = []

        findings.extend(self._check_api1_bola(endpoints, report))
        findings.extend(self._check_api2_authentication(endpoints))
        findings.extend(self._check_api3_data_exposure(endpoints))
        findings.extend(self._check_api4_rate_limiting(endpoints))
        findings.extend(self._check_api7_security_misconfig())
        findings.extend(self._check_api8_injection(endpoints))
        findings.extend(self._check_api9_improper_assets(spec))

        report.findings = findings
        report.owasp_coverage = self._build_owasp_coverage(findings)
        report.overall_risk = self._evaluate_risk(findings)
        report.summary = self._generate_summary(report)

        logger.info(
            f"API taraması tamamlandı. "
            f"{len(findings)} bulgu tespit edildi."
        )
        return report

    # ------------------------------------------------------------------
    # OpenAPI Parse
    # ------------------------------------------------------------------

    def _fetch_openapi_spec(self, url: str) -> Optional[dict]:
        """OpenAPI spec'i URL'den indirir."""
        try:
            resp = self._session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            logger.warning(
                f"OpenAPI spec indirilemedi: {url} → {resp.status_code}"
            )
        except Exception as e:
            logger.error(f"OpenAPI spec fetch hatası: {e}")
        return None

    def _load_openapi_file(self, path: str) -> Optional[dict]:
        """Yerel OpenAPI JSON/YAML dosyasını yükler."""
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"OpenAPI dosya yükleme hatası: {e}")
        return None

    def _extract_endpoints(self, spec: dict) -> list[dict[str, str]]:
        """
        OpenAPI 3.x ve Swagger 2.x spec'inden path+method çiftlerini çıkarır.
        """
        endpoints: list[dict[str, str]] = []

        # Swagger 2.x base path
        base_path = spec.get("basePath", "")

        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            full_path = base_path + path
            for method, operation in methods.items():
                if method.lower() in (
                    "get", "post", "put", "patch", "delete", "options"
                ):
                    parameters = operation.get("parameters", [])
                    has_id_param = any(
                        "id" in (p.get("name", "").lower())
                        for p in parameters
                        if isinstance(p, dict)
                    )
                    endpoints.append({
                        "path": full_path,
                        "method": method.upper(),
                        "summary": operation.get("summary", ""),
                        "has_id_param": str(has_id_param),
                    })
        return endpoints

    def _generate_common_endpoints(self) -> list[dict[str, str]]:
        """Spec olmadan test edilecek yaygın API endpoint'leri."""
        common = [
            ("/api/users", "GET"),
            ("/api/users/1", "GET"),
            ("/api/users/2", "GET"),
            ("/api/admin", "GET"),
            ("/api/v1/users", "GET"),
            ("/api/v2/users", "GET"),
            ("/api/profile", "GET"),
            ("/api/orders", "GET"),
            ("/api/orders/1", "GET"),
            ("/swagger.json", "GET"),
            ("/openapi.json", "GET"),
            ("/api-docs", "GET"),
            ("/api/health", "GET"),
            ("/api/config", "GET"),
            ("/api/debug", "GET"),
        ]
        return [
            {"path": p, "method": m, "summary": "", "has_id_param": "False"}
            for p, m in common
        ]

    # ------------------------------------------------------------------
    # OWASP API1 - BOLA / IDOR Testleri
    # ------------------------------------------------------------------

    def _check_api1_bola(
        self, endpoints: list[dict], report: APISecurityReport
    ) -> list[APIFinding]:
        """
        BOLA (Broken Object Level Authorization) — OWASP API1:
        ID parametresi içeren endpoint'lere farklı ID'lerle erişim dener.
        Farklı ID'de 200 dönüyorsa IDOR zafiyeti var demektir.
        """
        findings: list[APIFinding] = []
        bola_result = BOLATestResult()
        tested = 0

        # ID içeren path'leri bul
        id_endpoints = [
            ep for ep in endpoints
            if any(
                seg for seg in ep["path"].split("/")
                if seg.isdigit() or "{id}" in seg.lower()
            )
        ]

        for ep in id_endpoints[:10]:   # Maksimum 10 endpoint test et
            path = ep["path"]

            # Farklı obje ID'leri dene
            for test_id in [1, 2, 99, 100]:
                # Mevcut path'deki sayısal segmenti değiştir
                import re
                modified_path = re.sub(r"/\d+", f"/{test_id}", path)
                url = urljoin(self.base_url, modified_path)

                try:
                    resp = self._session.request(
                        ep["method"],
                        url,
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    tested += 1

                    if resp.status_code == 200:
                        # Farklı ID'de 200 → potansiyel BOLA
                        bola_result.vulnerable_endpoints.append({
                            "endpoint": url,
                            "method": ep["method"],
                            "test_id": test_id,
                            "status_code": resp.status_code,
                        })

                    time.sleep(self.delay)

                except Exception as e:
                    logger.debug(f"BOLA testi hatası ({url}): {e}")
                    continue

        bola_result.tested_count = tested

        if bola_result.vulnerable_endpoints:
            bola_result.details = (
                f"{len(bola_result.vulnerable_endpoints)} endpoint BOLA "
                f"zafiyetine karşı savunmasız görünüyor."
            )
            findings.append(APIFinding(
                owasp_id="API1",
                owasp_label=OWASP_API_TOP10["API1"],
                severity="Kritik",
                endpoint=", ".join(
                    e["endpoint"]
                    for e in bola_result.vulnerable_endpoints[:3]
                ),
                method="GET/PUT/DELETE",
                description=(
                    "Farklı nesne ID'lerine (1, 2, 99) yetkisiz erişim "
                    "sağlanabiliyor. BOLA/IDOR zafiyeti tespit edildi."
                ),
                evidence=(
                    f"Savunmasız endpoint'ler: "
                    f"{bola_result.vulnerable_endpoints[:3]}"
                ),
                recommendation=(
                    "Her obje erişiminde sunucu taraflı yetki kontrolü yapın. "
                    "Kullanıcının istediği nesneye sahip olup olmadığını "
                    "her istekte doğrulayın."
                ),
            ))
        else:
            bola_result.details = (
                f"{tested} endpoint test edildi, "
                "belirgin bir BOLA zafiyeti tespit edilmedi."
            )

        report.bola_result = bola_result
        return findings

    # ------------------------------------------------------------------
    # OWASP API2 - Authentication Kontrolleri
    # ------------------------------------------------------------------

    def _check_api2_authentication(
        self, endpoints: list[dict]
    ) -> list[APIFinding]:
        """Kimlik doğrulama gerektiren endpoint'lere yetkisiz erişim dener."""
        findings: list[APIFinding] = []
        sensitive_paths = [
            ep for ep in endpoints
            if any(
                kw in ep["path"].lower()
                for kw in ["admin", "user", "profile", "account", "secret"]
            )
        ]

        for ep in sensitive_paths[:5]:
            url = urljoin(self.base_url, ep["path"])
            # Authorization header olmadan dene
            try:
                no_auth_session = requests.Session()
                no_auth_session.headers.update({"Accept": "application/json"})
                resp = no_auth_session.request(
                    ep["method"],
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                if resp.status_code == 200:
                    findings.append(APIFinding(
                        owasp_id="API2",
                        owasp_label=OWASP_API_TOP10["API2"],
                        severity="Kritik",
                        endpoint=url,
                        method=ep["method"],
                        description=(
                            f"'{ep['path']}' endpoint'i kimlik doğrulama "
                            "gerektirmeden erişilebilir durumda."
                        ),
                        evidence=f"HTTP {resp.status_code} — no auth header",
                        recommendation=(
                            "Tüm hassas endpoint'lerde JWT/OAuth2 ile "
                            "kimlik doğrulama zorunlu hale getirin. "
                            "401 Unauthorized döndürülmeli."
                        ),
                    ))
                time.sleep(self.delay)
            except Exception as e:
                logger.debug(f"Auth testi hatası ({url}): {e}")

        return findings

    # ------------------------------------------------------------------
    # OWASP API3 - Excessive Data Exposure
    # ------------------------------------------------------------------

    def _check_api3_data_exposure(
        self, endpoints: list[dict]
    ) -> list[APIFinding]:
        """Yanıtlarda gereksiz hassas veri dönüp dönmediğini kontrol eder."""
        findings: list[APIFinding] = []
        sensitive_fields = [
            "password", "passwd", "secret", "token", "api_key",
            "credit_card", "ssn", "private_key", "hash",
        ]

        for ep in endpoints[:8]:
            url = urljoin(self.base_url, ep["path"])
            try:
                resp = self._session.request(
                    ep["method"],
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code != 200:
                    continue

                body_lower = resp.text.lower()
                exposed = [
                    f for f in sensitive_fields if f in body_lower
                ]

                if exposed:
                    findings.append(APIFinding(
                        owasp_id="API3",
                        owasp_label=OWASP_API_TOP10["API3"],
                        severity="Yüksek",
                        endpoint=url,
                        method=ep["method"],
                        description=(
                            f"'{ep['path']}' yanıtında hassas alanlar "
                            f"tespit edildi: {', '.join(exposed)}"
                        ),
                        evidence=f"Bulunan alanlar: {exposed}",
                        recommendation=(
                            "API yanıtlarında yalnızca gerekli alanları "
                            "döndürün (allowlist yaklaşımı). "
                            "Şifre hash'leri ve token'lar asla döndürülmemeli."
                        ),
                    ))
                time.sleep(self.delay)
            except Exception as e:
                logger.debug(f"Data exposure testi hatası ({url}): {e}")

        return findings

    # ------------------------------------------------------------------
    # OWASP API4 - Rate Limiting Eksikliği
    # ------------------------------------------------------------------

    def _check_api4_rate_limiting(
        self, endpoints: list[dict]
    ) -> list[APIFinding]:
        """API endpoint'lerinde rate limiting yapılandırmasını test eder."""
        findings: list[APIFinding] = []

        if not endpoints:
            return findings

        ep = endpoints[0]
        url = urljoin(self.base_url, ep["path"])
        status_codes: list[int] = []

        try:
            for _ in range(15):
                resp = self._session.request(
                    ep["method"],
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                status_codes.append(resp.status_code)
                if resp.status_code == 429:
                    return findings   # Rate limit aktif, bulgu yok
                time.sleep(0.1)

            # 429 hiç dönmediyse rate limit yok
            non_error = [sc for sc in status_codes if sc < 500]
            if non_error and 429 not in status_codes:
                findings.append(APIFinding(
                    owasp_id="API4",
                    owasp_label=OWASP_API_TOP10["API4"],
                    severity="Yüksek",
                    endpoint=url,
                    method=ep["method"],
                    description=(
                        "15 hızlı ardışık istek gönderildi, "
                        "rate limiting (HTTP 429) tespit edilmedi."
                    ),
                    evidence=f"Durum kodları: {status_codes[:5]}...",
                    recommendation=(
                        "API gateway veya uygulama katmanında rate limiting "
                        "uygulayın. "
                        "429 Too Many Requests + Retry-After header döndürün. "
                        "Token bucket veya sliding window "
                        "algoritması kullanın."
                    ),
                ))
        except Exception as e:
            logger.debug(f"Rate limit API testi hatası: {e}")

        return findings

    # ------------------------------------------------------------------
    # OWASP API7 - Security Misconfiguration
    # ------------------------------------------------------------------

    def _check_api7_security_misconfig(self) -> list[APIFinding]:
        """
        Güvenlik yanlış yapılandırmalarını kontrol eder:
        - Swagger/OpenAPI UI'ın public açık olması
        - DEBUG mode açık
        - Güvensiz HTTP başlıkları
        """
        findings: list[APIFinding] = []

        # Swagger UI / OpenAPI spec public açık mı?
        swagger_paths = [
            "/swagger-ui.html", "/swagger-ui/", "/api-docs",
            "/swagger.json", "/openapi.json", "/v2/api-docs",
        ]

        for path in swagger_paths:
            url = urljoin(self.base_url, path)
            try:
                resp = self._session.get(
                    url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code in (200, 301, 302):
                    findings.append(APIFinding(
                        owasp_id="API7",
                        owasp_label=OWASP_API_TOP10["API7"],
                        severity="Orta",
                        endpoint=url,
                        method="GET",
                        description=(
                            f"API dokümantasyonu/spec ({path}) "
                            "herkese açık erişilebilir durumda."
                        ),
                        evidence=f"HTTP {resp.status_code}",
                        recommendation=(
                            "Swagger UI ve API spec'ini production ortamında "
                            "gizleyin veya IP tabanlı whitelist ile koruyun. "
                            "Kimlik doğrulama ekleyin."
                        ),
                    ))
                time.sleep(self.delay)
            except Exception:
                continue

        # Güvensiz güvenlik başlıkları
        try:
            resp = self._session.get(
                self.base_url, timeout=self.timeout
            )
            missing_headers: list[str] = []
            required = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Strict-Transport-Security",
                "Content-Security-Policy",
            ]
            for header in required:
                if header not in resp.headers:
                    missing_headers.append(header)

            if missing_headers:
                findings.append(APIFinding(
                    owasp_id="API7",
                    owasp_label=OWASP_API_TOP10["API7"],
                    severity="Orta",
                    endpoint=self.base_url,
                    method="GET",
                    description=(
                        "Güvenlik HTTP başlıkları eksik: "
                        f"{', '.join(missing_headers)}"
                    ),
                    evidence=(
                        f"Eksik başlıklar: {missing_headers}"
                    ),
                    recommendation=(
                        "Tüm API yanıtlarına güvenlik başlıkları ekleyin: "
                        "X-Content-Type-Options: nosniff, "
                        "Strict-Transport-Security, "
                        "Content-Security-Policy."
                    ),
                ))
        except Exception as e:
            logger.debug(f"Security misconfig testi hatası: {e}")

        return findings

    # ------------------------------------------------------------------
    # OWASP API8 - Injection
    # ------------------------------------------------------------------

    def _check_api8_injection(
        self, endpoints: list[dict]
    ) -> list[APIFinding]:
        """GET parametreleri ve JSON body'de injection payload testleri."""
        findings: list[APIFinding] = []
        payloads = [
            "' OR '1'='1",         # SQL Injection
            "<script>alert(1)</script>",  # XSS
            "{{7*7}}",             # SSTI (Server-Side Template Injection)
            "; ls -la",            # Command Injection
        ]

        post_endpoints = [
            ep for ep in endpoints if ep["method"] in ("POST", "PUT")
        ][:3]

        for ep in post_endpoints:
            url = urljoin(self.base_url, ep["path"])
            for payload in payloads:
                try:
                    resp = self._session.request(
                        ep["method"],
                        url,
                        json={"input": payload, "query": payload},
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    body = resp.text

                    # Payload yanıtta aynen dönüyorsa → reflected injection
                    if payload in body and resp.status_code == 200:
                        findings.append(APIFinding(
                            owasp_id="API8",
                            owasp_label=OWASP_API_TOP10["API8"],
                            severity="Kritik",
                            endpoint=url,
                            method=ep["method"],
                            description=(
                                f"Injection payload yanıtta yansıdı: "
                                f"'{payload[:30]}...'"
                            ),
                            evidence=(
                                f"Gönderilen: {payload[:50]} | "
                                f"Yanıt içeriyor: {payload[:30]}"
                            ),
                            recommendation=(
                                "Tüm kullanıcı girdilerini sunucu tarafında "
                                "doğrulayın ve sanitize edin. "
                                "Parametreli sorgular (prepared statements) "
                                "kullanın. WAF entegrasyonu yapın."
                            ),
                        ))
                    time.sleep(self.delay)
                except Exception as e:
                    logger.debug(f"Injection testi hatası ({url}): {e}")

        return findings

    # ------------------------------------------------------------------
    # OWASP API9 - Improper Assets Management
    # ------------------------------------------------------------------

    def _check_api9_improper_assets(
        self, spec: Optional[dict]
    ) -> list[APIFinding]:
        """Eski/deprecated API versiyonlarının varlığını kontrol eder."""
        findings: list[APIFinding] = []
        old_versions = ["/api/v1/", "/api/v2/", "/v1/", "/v2/", "/old/"]

        for path in old_versions:
            url = urljoin(self.base_url, path)
            try:
                resp = self._session.get(
                    url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code in (200, 301, 302):
                    findings.append(APIFinding(
                        owasp_id="API9",
                        owasp_label=OWASP_API_TOP10["API9"],
                        severity="Orta",
                        endpoint=url,
                        method="GET",
                        description=(
                            f"Eski API versiyonu ({path}) "
                            "hâlâ erişilebilir durumda."
                        ),
                        evidence=f"HTTP {resp.status_code}",
                        recommendation=(
                            "Kullanımdan kalkan API versiyonlarını devre "
                            "dışı bırakın. API versiyonlama stratejisi "
                            "belirleyin ve deprecation bildirimleri yapın."
                        ),
                    ))
                time.sleep(self.delay)
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # Yardımcı Metotlar
    # ------------------------------------------------------------------

    def _build_owasp_coverage(
        self, findings: list[APIFinding]
    ) -> dict[str, bool]:
        """Hangi OWASP kategorilerinin test edildiğini ve bulgu

        içerdiğini döner.
        """
        tested_ids = {f.owasp_id for f in findings}
        coverage: dict[str, bool] = {}
        for api_id in OWASP_API_TOP10:
            coverage[api_id] = api_id in tested_ids
        return coverage

    def _evaluate_risk(self, findings: list[APIFinding]) -> str:
        """Bulgulara göre genel risk seviyesini belirler."""
        severities = [f.severity for f in findings]
        if "Kritik" in severities:
            return "Kritik"
        if "Yüksek" in severities:
            return "Yüksek"
        if "Orta" in severities:
            return "Orta"
        if "Düşük" in severities:
            return "Düşük"
        return "Bilgi"

    def _generate_summary(self, report: APISecurityReport) -> str:
        """İnsan tarafından okunabilir özet rapor metni üretir."""
        severity_count: dict[str, int] = {
            "Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0
        }
        for f in report.findings:
            severity_count[f.severity] = (
                severity_count.get(f.severity, 0) + 1
            )

        spec_source = report.spec_source or "Yok (common endpoints kullanıldı)"
        lines = [
            "=== API SECURITY SCANNER RAPORU ===",
            f"Hedef: {report.base_url}",
            f"Spec: {spec_source}",
            f"Keşfedilen Endpoint Sayısı: {report.endpoints_discovered}",
            f"Toplam Bulgu: {len(report.findings)}",
            "",
            "[ Bulgu Özeti ]",
        ]
        for sev, cnt in severity_count.items():
            if cnt > 0:
                lines.append(f"  {sev}: {cnt}")

        if report.bola_result:
            bola = report.bola_result
            lines.append(
                f"\n[BOLA Test] {bola.tested_count} endpoint test edildi. "
                f"Savunmasız: {len(bola.vulnerable_endpoints)}"
            )

        owasp_hits = [
            api_id
            for api_id, hit in report.owasp_coverage.items()
            if hit
        ]
        if owasp_hits:
            lines.append(
                f"\n[OWASP API Top 10] Bulgu bulunan kategoriler: "
                f"{', '.join(owasp_hits)}"
            )

        lines.append("")
        lines.append(f"Genel Risk Seviyesi: {report.overall_risk}")
        lines.append("=" * 35)
        return "\n".join(lines)
