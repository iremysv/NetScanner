# -*- coding: utf-8 -*-
"""
Tests/test_api_scanner.py

Unit testler: APISecurityScanner sınıfını gerçek ağ bağlantısı olmadan
(requests monkeypatch ve sahte OpenAPI spec ile) doğrular.
"""
import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

import pytest  # noqa: E402

from modules.api_scanner.scanner import (  # noqa: E402
    APISecurityScanner,
    APIFinding,
    APISecurityReport,
    OWASP_API_TOP10,
)


# ---------------------------------------------------------------------------
# Mock Yardımcılar
# ---------------------------------------------------------------------------

class MockResponse:
    """Sahte requests.Response."""
    def __init__(
        self,
        status_code: int = 200,
        text: str = "{}",
        headers: dict | None = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "application/json"}

    def json(self):
        import json
        try:
            return json.loads(self.text)
        except Exception:
            return {}


SAMPLE_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/api/users/{id}": {
            "get": {
                "summary": "Get user by ID",
                "parameters": [
                    {"name": "id", "in": "path", "required": True}
                ],
            }
        },
        "/api/users": {
            "get": {"summary": "List users"},
            "post": {"summary": "Create user"},
        },
        "/api/admin": {
            "get": {"summary": "Admin panel"},
        },
    },
}


# ---------------------------------------------------------------------------
# OpenAPI Parse Testleri
# ---------------------------------------------------------------------------

class TestOpenAPIParse:
    """_extract_endpoints ve spec parse işlemlerini doğrular."""

    def test_extracts_correct_endpoint_count(self):
        """Spec'teki path sayısı doğru çıkarılmalı."""
        scanner = APISecurityScanner("http://fake.test")
        endpoints = scanner._extract_endpoints(SAMPLE_OPENAPI_SPEC)
        # /api/users/{id} GET, /api/users GET+POST, /api/admin GET = 4 endpoint
        assert len(endpoints) >= 3

    def test_extracts_methods_correctly(self):
        """HTTP metodları (GET, POST) doğru çıkarılmalı."""
        scanner = APISecurityScanner("http://fake.test")
        endpoints = scanner._extract_endpoints(SAMPLE_OPENAPI_SPEC)
        methods = {ep["method"] for ep in endpoints}
        assert "GET" in methods
        assert "POST" in methods

    def test_has_id_param_detected(self):
        """ID parametresi içeren endpoint doğru işaretlenmeli."""
        scanner = APISecurityScanner("http://fake.test")
        endpoints = scanner._extract_endpoints(SAMPLE_OPENAPI_SPEC)
        id_endpoints = [ep for ep in endpoints if ep["has_id_param"] == "True"]
        assert len(id_endpoints) > 0

    def test_empty_spec_returns_empty_list(self):
        """Boş spec → boş endpoint listesi."""
        scanner = APISecurityScanner("http://fake.test")
        result = scanner._extract_endpoints({})
        assert result == []

    def test_load_openapi_file_returns_none_on_missing(self, tmp_path):
        """Var olmayan dosya için None döndürülmeli."""
        scanner = APISecurityScanner("http://fake.test")
        result = scanner._load_openapi_file(str(tmp_path / "nofile.json"))
        assert result is None

    def test_load_openapi_file_reads_valid_json(self, tmp_path):
        """Geçerli JSON dosyası doğru okunmalı."""
        import json
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_SPEC), encoding="utf-8")

        scanner = APISecurityScanner("http://fake.test")
        result = scanner._load_openapi_file(str(spec_file))
        assert result is not None
        assert "paths" in result

    def test_generate_common_endpoints_not_empty(self):
        """Spec olmadan yaygın endpoint listesi oluşturulabilmeli."""
        scanner = APISecurityScanner("http://fake.test")
        endpoints = scanner._generate_common_endpoints()
        assert len(endpoints) > 0
        assert all("path" in ep and "method" in ep for ep in endpoints)


# ---------------------------------------------------------------------------
# APIFinding Testleri
# ---------------------------------------------------------------------------

class TestAPIFinding:
    """APIFinding dataclass doğrulamaları."""

    def test_finding_has_required_fields(self):
        """APIFinding zorunlu alanları içermeli."""
        finding = APIFinding(
            owasp_id="API1",
            owasp_label="BOLA",
            severity="Kritik",
            endpoint="/api/users/1",
            method="GET",
            description="BOLA tespit edildi",
        )
        assert finding.owasp_id == "API1"
        assert finding.severity == "Kritik"

    def test_finding_default_evidence_empty(self):
        """evidence alanı varsayılan boş olmalı."""
        finding = APIFinding(
            owasp_id="API7",
            owasp_label="Misconfig",
            severity="Orta",
            endpoint="/",
            method="GET",
            description="Test",
        )
        assert finding.evidence == ""


# ---------------------------------------------------------------------------
# OWASP API7 - Security Misconfig Testleri
# ---------------------------------------------------------------------------

class TestSecurityMisconfig:
    """API7 — güvenlik yanlış yapılandırma kontrolleri."""

    def test_detects_swagger_ui_exposed(self, monkeypatch):
        """Swagger UI erişilebilirse API7 bulgusu oluşmalı."""
        def mock_get(url, *args, **kwargs):
            if "swagger" in url.lower() or "api-docs" in url.lower():
                return MockResponse(200, "swagger-ui")
            return MockResponse(404, "not found")

        scanner = APISecurityScanner("http://fake.test")
        monkeypatch.setattr(scanner._session, "get", mock_get)

        findings = scanner._check_api7_security_misconfig()
        owasp_ids = [f.owasp_id for f in findings]
        assert "API7" in owasp_ids

    def test_missing_security_headers_generates_finding(self, monkeypatch):
        """Güvenlik başlıkları eksikse API7 bulgusu oluşmalı."""
        def mock_get(url, *args, **kwargs):
            # Hiçbir güvenlik başlığı yok
            return MockResponse(200, "{}", headers={"Content-Type": "application/json"})

        scanner = APISecurityScanner("http://fake.test")
        monkeypatch.setattr(scanner._session, "get", mock_get)

        findings = scanner._check_api7_security_misconfig()
        security_findings = [
            f for f in findings
            if "başlık" in f.description.lower() or "header" in f.description.lower()
        ]
        assert len(security_findings) > 0

    def test_no_finding_when_swagger_404(self, monkeypatch):
        """Swagger 404 dönünce API7 swagger bulgusu olmamalı."""
        def mock_get(url, *args, **kwargs):
            return MockResponse(404, "not found", headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
            })

        scanner = APISecurityScanner("http://fake.test")
        monkeypatch.setattr(scanner._session, "get", mock_get)

        findings = scanner._check_api7_security_misconfig()
        swagger_findings = [
            f for f in findings if "swagger" in f.description.lower()
        ]
        assert swagger_findings == []


# ---------------------------------------------------------------------------
# OWASP API4 - Rate Limiting Testleri
# ---------------------------------------------------------------------------

class TestRateLimitingCheck:
    """API4 — rate limiting kontrolleri."""

    def test_detects_missing_rate_limit(self, monkeypatch):
        """429 hiç dönmezse API4 bulgusu oluşmalı."""
        def mock_request(method, url, *args, **kwargs):
            return MockResponse(200, "{}")

        scanner = APISecurityScanner("http://fake.test", delay=0)
        monkeypatch.setattr(scanner._session, "request", mock_request)

        endpoints = [{"path": "/api/test", "method": "GET", "summary": "", "has_id_param": "False"}]
        findings = scanner._check_api4_rate_limiting(endpoints)
        assert any(f.owasp_id == "API4" for f in findings)

    def test_no_finding_when_429_returned(self, monkeypatch):
        """429 dönünce API4 bulgusu olmamalı."""
        def mock_request(method, url, *args, **kwargs):
            return MockResponse(429, "Too Many Requests")

        scanner = APISecurityScanner("http://fake.test", delay=0)
        monkeypatch.setattr(scanner._session, "request", mock_request)

        endpoints = [{"path": "/api/test", "method": "GET", "summary": "", "has_id_param": "False"}]
        findings = scanner._check_api4_rate_limiting(endpoints)
        api4_findings = [f for f in findings if f.owasp_id == "API4"]
        assert api4_findings == []

    def test_empty_endpoints_no_error(self, monkeypatch):
        """Boş endpoint listesi exception fırlatmamalı."""
        scanner = APISecurityScanner("http://fake.test", delay=0)
        findings = scanner._check_api4_rate_limiting([])
        assert findings == []


# ---------------------------------------------------------------------------
# OWASP Kapsama ve Risk Değerlendirme Testleri
# ---------------------------------------------------------------------------

class TestRiskEvaluation:
    """Risk değerlendirme ve OWASP kapsama."""

    def test_critical_finding_leads_to_critical_risk(self):
        """Kritik bulgu varsa risk Kritik olmalı."""
        scanner = APISecurityScanner("http://fake.test")
        findings = [
            APIFinding(
                owasp_id="API1",
                owasp_label="BOLA",
                severity="Kritik",
                endpoint="/api/1",
                method="GET",
                description="BOLA",
            )
        ]
        risk = scanner._evaluate_risk(findings)
        assert risk == "Kritik"

    def test_no_findings_returns_bilgi(self):
        """Bulgu yoksa risk Bilgi olmalı."""
        scanner = APISecurityScanner("http://fake.test")
        risk = scanner._evaluate_risk([])
        assert risk == "Bilgi"

    def test_owasp_coverage_keys_match_top10(self):
        """OWASP kapsama sözlüğü tüm API1-API10 anahtarlarını içermeli."""
        scanner = APISecurityScanner("http://fake.test")
        findings = [
            APIFinding("API1", "BOLA", "Kritik", "/", "GET", "test"),
            APIFinding("API7", "Misconfig", "Orta", "/", "GET", "test"),
        ]
        coverage = scanner._build_owasp_coverage(findings)
        for api_id in OWASP_API_TOP10:
            assert api_id in coverage

    def test_owasp_coverage_true_for_hit(self):
        """Bulgu olan OWASP kategorisi True olmalı."""
        scanner = APISecurityScanner("http://fake.test")
        findings = [
            APIFinding("API1", "BOLA", "Kritik", "/", "GET", "test")
        ]
        coverage = scanner._build_owasp_coverage(findings)
        assert coverage.get("API1") is True

    def test_owasp_coverage_false_for_no_hit(self):
        """Bulgu olmayan OWASP kategorisi False olmalı."""
        scanner = APISecurityScanner("http://fake.test")
        findings = []
        coverage = scanner._build_owasp_coverage(findings)
        assert coverage.get("API1") is False


# ---------------------------------------------------------------------------
# APISecurityReport Testleri
# ---------------------------------------------------------------------------

class TestAPISecurityReport:
    """APISecurityReport dataclass doğrulamaları."""

    def test_report_defaults(self):
        """Varsayılan rapor alanları doğru olmalı."""
        report = APISecurityReport(base_url="http://test.com")
        assert report.findings == []
        assert report.endpoints_discovered == 0
        assert report.overall_risk == "Bilinmiyor"

    def test_summary_generated(self, monkeypatch):
        """_generate_summary metni boş olmamalı."""
        def mock_get(*args, **kwargs):
            return MockResponse(404, "not found", headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "ok",
                "Content-Security-Policy": "ok",
            })

        def mock_request(*args, **kwargs):
            return MockResponse(404, "not found")

        scanner = APISecurityScanner("http://fake.test", delay=0)
        monkeypatch.setattr(scanner._session, "get", mock_get)
        monkeypatch.setattr(scanner._session, "request", mock_request)

        report = scanner.scan(spec_dict=SAMPLE_OPENAPI_SPEC)
        assert isinstance(report.summary, str)
        assert len(report.summary) > 0
