# -*- coding: utf-8 -*-
"""
Tests/test_credential_tester.py

Unit testler: CredentialTester sınıfını gerçek ağ bağlantısı olmadan
(requests monkeypatch ile) doğrular.
"""
import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

import pytest  # noqa: E402
import requests  # noqa: E402

from modules.credential_tester.tester import (  # noqa: E402
    CredentialTester,
    RateLimitResult,
    PasswordPolicyResult,
    LockoutResult,
    CredentialTestReport,
    WEAK_PASSWORDS,
)


# ---------------------------------------------------------------------------
# Mock Yardımcılar
# ---------------------------------------------------------------------------

class MockResponse:
    """Sahte requests.Response nesnesi."""
    def __init__(
        self,
        status_code: int,
        text: str = "",
        headers: dict | None = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def json(self):
        import json
        return json.loads(self.text) if self.text else {}


# ---------------------------------------------------------------------------
# RateLimitResult Testleri
# ---------------------------------------------------------------------------

class TestRateLimitResult:
    """RateLimitResult dataclass doğrulamaları."""

    def test_default_detected_false(self):
        r = RateLimitResult(detected=False, requests_sent=0, trigger_request=-1)
        assert r.detected is False

    def test_detected_true(self):
        r = RateLimitResult(detected=True, requests_sent=5, trigger_request=5)
        assert r.detected is True
        assert r.trigger_request == 5

    def test_retry_after_none_by_default(self):
        r = RateLimitResult(detected=True, requests_sent=3, trigger_request=3)
        assert r.retry_after is None


# ---------------------------------------------------------------------------
# PasswordPolicyResult Testleri
# ---------------------------------------------------------------------------

class TestPasswordPolicyResult:
    """PasswordPolicyResult dataclass doğrulamaları."""

    def test_empty_weak_list(self):
        r = PasswordPolicyResult()
        assert r.weak_passwords_found == []

    def test_policy_score_default(self):
        r = PasswordPolicyResult()
        assert r.policy_score == 0


# ---------------------------------------------------------------------------
# CredentialTester.test_rate_limiting() Testleri
# ---------------------------------------------------------------------------

class TestTestRateLimiting:
    """Rate limit test metodunu doğrular."""

    def test_detects_429_response(self, monkeypatch):
        """429 döndüğünde rate limiting tespit edilmeli."""
        call_count = {"n": 0}

        def mock_post(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] >= 3:
                return MockResponse(429, "", {"Retry-After": "60"})
            return MockResponse(200, "Login page")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_rate_limiting(max_requests=10)
        assert result.detected is True
        assert result.trigger_request == 3
        assert result.retry_after == 60

    def test_no_rate_limit_returns_detected_false(self, monkeypatch):
        """429 hiç dönmezse rate limiting bulunamadı dönmeli."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "Invalid credentials")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_rate_limiting(max_requests=5)
        assert result.detected is False
        assert result.requests_sent == 5

    def test_connection_error_handled_gracefully(self, monkeypatch):
        """Bağlantı hatası exception fırlatmamalı."""
        def mock_post(*args, **kwargs):
            raise requests.exceptions.ConnectionError("bağlantı hatası")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_rate_limiting(max_requests=5)
        assert isinstance(result, RateLimitResult)

    def test_503_also_detected_as_rate_limit(self, monkeypatch):
        """503 yanıtı da rate limiting olarak işaretlenmeli."""
        def mock_post(*args, **kwargs):
            return MockResponse(503, "Service Unavailable")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_rate_limiting(max_requests=3)
        assert result.detected is True

    def test_requests_sent_counted(self, monkeypatch):
        """Gönderilen istek sayısı doğru sayılmalı."""
        def mock_post(*args, **kwargs):
            return MockResponse(200, "ok")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_rate_limiting(max_requests=7)
        assert result.requests_sent == 7


# ---------------------------------------------------------------------------
# CredentialTester.test_password_policy() Testleri
# ---------------------------------------------------------------------------

class TestTestPasswordPolicy:
    """Parola politikası test metodunu doğrular."""

    def test_returns_password_policy_result(self, monkeypatch):
        """Sonuç PasswordPolicyResult tipinde olmalı."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "Invalid password")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_password_policy(weak_list=["123456"])
        assert isinstance(result, PasswordPolicyResult)

    def test_weak_password_found_when_200_and_no_error(self, monkeypatch):
        """200 dönünce ve hata mesajı yoksa zayıf parola kabul edilmiş sayılır."""
        def mock_post(*args, **kwargs):
            return MockResponse(200, "Welcome to the dashboard")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_password_policy(weak_list=["password", "123456"])
        assert len(result.weak_passwords_found) > 0

    def test_weak_password_not_found_when_error_in_body(self, monkeypatch):
        """Yanıtta 'invalid' geçiyorsa zayıf parola kabul edilmemiş sayılır."""
        def mock_post(*args, **kwargs):
            return MockResponse(200, "Invalid credentials. Please try again.")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_password_policy(weak_list=["password"])
        assert result.weak_passwords_found == []

    def test_policy_score_decreases_with_weak_passwords(self, monkeypatch):
        """Zayıf parola bulununca skor düşmeli."""
        def mock_post(*args, **kwargs):
            return MockResponse(200, "Welcome!")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_password_policy(weak_list=["pass1", "pass2", "pass3"])
        assert result.policy_score < 100

    def test_details_not_empty(self, monkeypatch):
        """Details alanı boş olmamalı."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "error")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_password_policy(weak_list=["123456"])
        assert len(result.details) > 0


# ---------------------------------------------------------------------------
# CredentialTester.test_account_lockout() Testleri
# ---------------------------------------------------------------------------

class TestTestAccountLockout:
    """Account lockout test metodunu doğrular."""

    def test_detects_lockout_from_body_keyword(self, monkeypatch):
        """Yanıt gövdesinde 'locked' geçince lockout tespit edilmeli."""
        call_count = {"n": 0}

        def mock_post(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] >= 4:
                return MockResponse(200, "Your account has been locked.")
            return MockResponse(401, "Invalid credentials")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_account_lockout(max_attempts=8)
        assert result.lockout_detected is True
        assert result.failed_attempts_before_lock == 4

    def test_detects_lockout_from_status_423(self, monkeypatch):
        """HTTP 423 dönünce lockout tespit edilmeli."""
        call_count = {"n": 0}

        def mock_post(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] >= 3:
                return MockResponse(423, "Locked")
            return MockResponse(401, "Invalid")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_account_lockout(max_attempts=8)
        assert result.lockout_detected is True
        assert result.lockout_status_code == 423

    def test_no_lockout_detected(self, monkeypatch):
        """Lockout yoksa detected=False dönmeli."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "Wrong password")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_account_lockout(max_attempts=5)
        assert result.lockout_detected is False

    def test_connection_error_treated_as_lockout(self, monkeypatch):
        """Bağlantı kesilmesi IP lockout olarak değerlendirilmeli."""
        call_count = {"n": 0}

        def mock_post(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                raise requests.exceptions.ConnectionError("Bağlantı kesildi")
            return MockResponse(401, "Wrong")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        result = tester.test_account_lockout(max_attempts=8)
        assert result.lockout_detected is True


# ---------------------------------------------------------------------------
# CredentialTester.run_all_tests() Testleri
# ---------------------------------------------------------------------------

class TestRunAllTests:
    """run_all_tests() bütünleşik testleri."""

    def test_returns_credential_test_report(self, monkeypatch):
        """Sonuç CredentialTestReport tipinde olmalı."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "invalid")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        report = tester.run_all_tests(max_rate_requests=3, lockout_attempts=3)
        assert isinstance(report, CredentialTestReport)

    def test_report_has_all_sections(self, monkeypatch):
        """Rapor rate_limit, password_policy ve lockout içermeli."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "error")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        report = tester.run_all_tests(max_rate_requests=3, lockout_attempts=3)
        assert report.rate_limit is not None
        assert report.password_policy is not None
        assert report.lockout is not None

    def test_overall_risk_is_string(self, monkeypatch):
        """Genel risk seviyesi string olmalı."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "error")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        report = tester.run_all_tests(max_rate_requests=2, lockout_attempts=2)
        assert isinstance(report.overall_risk, str)
        assert report.overall_risk in ("Kritik", "Yüksek", "Orta", "Düşük")

    def test_summary_contains_target_url(self, monkeypatch):
        """Özet metni hedef URL'yi içermeli."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "error")

        target = "http://fake.test/login"
        tester = CredentialTester(target, delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        report = tester.run_all_tests(max_rate_requests=2, lockout_attempts=2)
        assert target in report.summary

    def test_no_rate_limit_leads_to_high_risk(self, monkeypatch):
        """Rate limit ve lockout yoksa risk Yüksek veya Kritik olmalı."""
        def mock_post(*args, **kwargs):
            return MockResponse(401, "error")

        tester = CredentialTester("http://fake.test/login", delay_between_requests=0)
        monkeypatch.setattr(tester._session, "post", mock_post)

        report = tester.run_all_tests(max_rate_requests=5, lockout_attempts=5)
        assert report.overall_risk in ("Yüksek", "Kritik")
