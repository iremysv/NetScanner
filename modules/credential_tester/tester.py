# -*- coding: utf-8 -*-
"""
modules/credential_tester/tester.py

Credential Tester Modülü:
- Rate limiting tespiti (kısa sürede çok fazla istek → 429 Too Many Requests)
- Parola politikası kontrolü (zayıf parola listesi ile karşılaştırma)
- Account lockout tespiti (başarısız giriş denemeleri → hesap kilitleme)

Gerçek bir brute-force saldırısı YAPMAZ. Hedef servisi analiz ederek
bu güvenlik önlemlerinin doğru yapılandırılıp yapılandırılmadığını test eder.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger("CredentialTester")

# -------------------------------------------------------------------------
# Zayıf Parola Listesi (OWASP Top 25 Weak Passwords)
# -------------------------------------------------------------------------
WEAK_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustafa", "iloveyou", "admin", "welcome",
    "login", "passw0rd", "password1", "hello", "dragon",
]

# -------------------------------------------------------------------------
# Veri Sınıfları
# -------------------------------------------------------------------------

@dataclass
class RateLimitResult:
    """Rate limiting test sonucu."""
    detected: bool
    requests_sent: int
    trigger_request: int          # Kaçıncı istekte tetiklendi
    status_codes: list[int] = field(default_factory=list)
    retry_after: Optional[int] = None   # Retry-After header değeri (saniye)
    details: str = ""


@dataclass
class PasswordPolicyResult:
    """Parola politikası analiz sonucu."""
    weak_passwords_found: list[str] = field(default_factory=list)
    policy_score: int = 0       # 0-100 arası puan
    min_length_ok: bool = False
    has_uppercase: bool = False
    has_digit: bool = False
    has_special: bool = False
    details: str = ""


@dataclass
class LockoutResult:
    """Account lockout test sonucu."""
    lockout_detected: bool
    failed_attempts_before_lock: int
    lockout_status_code: Optional[int] = None
    lockout_message: str = ""
    details: str = ""


@dataclass
class CredentialTestReport:
    """Credential Tester ana rapor nesnesi."""
    target_url: str
    rate_limit: Optional[RateLimitResult] = None
    password_policy: Optional[PasswordPolicyResult] = None
    lockout: Optional[LockoutResult] = None
    overall_risk: str = "Bilinmiyor"   # Kritik / Yüksek / Orta / Düşük
    summary: str = ""


# -------------------------------------------------------------------------
# Ana Sınıf
# -------------------------------------------------------------------------

class CredentialTester:
    """
    Bir HTTP(S) login endpoint'ini analiz ederek:
    1. Rate limiting'in aktif olup olmadığını test eder.
    2. Parola politikasını analiz eder (zayıf parola listesi).
    3. Account lockout mekanizmasının çalışıp çalışmadığını test eder.

    Kullanım:
        tester = CredentialTester("https://hedef.com/login")
        rapor = tester.run_all_tests()
    """

    def __init__(
        self,
        target_url: str,
        username_field: str = "username",
        password_field: str = "password",
        timeout: int = 5,
        delay_between_requests: float = 0.3,
    ) -> None:
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.timeout = timeout
        self.delay = delay_between_requests
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": (
                "NetScanner-CredentialTester/1.0 "
                "(Security Research Tool - Authorized Testing Only)"
            )
        })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_all_tests(
        self,
        test_username: str = "testuser",
        max_rate_requests: int = 20,
        lockout_attempts: int = 10,
    ) -> CredentialTestReport:
        """
        Tüm testleri sırayla çalıştırır ve birleşik rapor döner.

        Args:
            test_username: Test kullanıcı adı (gerçek olmayan)
            max_rate_requests: Rate limit testi için gönderilecek istek sayısı
            lockout_attempts: Lockout testi için maksimum deneme sayısı

        Returns:
            CredentialTestReport nesnesi
        """
        logger.info(f"Credential Tester başlatıldı → Hedef: {self.target_url}")

        report = CredentialTestReport(target_url=self.target_url)

        # 1. Rate Limit Testi
        logger.info("[1/3] Rate limit testi çalışıyor...")
        report.rate_limit = self.test_rate_limiting(
            test_username, max_rate_requests
        )

        # 2. Parola Politikası Testi
        logger.info("[2/3] Parola politikası analizi...")
        report.password_policy = self.test_password_policy()

        # 3. Account Lockout Testi
        logger.info("[3/3] Account lockout testi çalışıyor...")
        report.lockout = self.test_account_lockout(
            test_username, lockout_attempts
        )

        # Genel risk değerlendirmesi
        report.overall_risk = self._evaluate_overall_risk(report)
        report.summary = self._generate_summary(report)

        logger.info("Credential Tester tamamlandı.")
        return report

    def test_rate_limiting(
        self,
        username: str = "testuser",
        max_requests: int = 20,
    ) -> RateLimitResult:
        """
        Hedef endpoint'e hızlı ardışık istekler göndererek
        rate limiting mekanizmasının aktif olup olmadığını test eder.
        429 Too Many Requests veya Retry-After header tespit edilirse
        rate limiting bulunmuş sayılır.
        """
        status_codes: list[int] = []
        trigger_request = -1
        retry_after = None

        for i in range(1, max_requests + 1):
            try:
                payload = {
                    self.username_field: username,
                    self.password_field: f"test_rate_{i}",
                }
                resp = self._session.post(
                    self.target_url,
                    data=payload,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                status_codes.append(resp.status_code)

                # Rate limit tespit koşulları
                if resp.status_code == 429:
                    trigger_request = i
                    retry_after_header = resp.headers.get("Retry-After")
                    if retry_after_header:
                        try:
                            retry_after = int(retry_after_header)
                        except ValueError:
                            pass
                    return RateLimitResult(
                        detected=True,
                        requests_sent=i,
                        trigger_request=trigger_request,
                        status_codes=status_codes,
                        retry_after=retry_after,
                        details=(
                            f"{i}. istekte 429 Too Many Requests alındı. "
                            f"Retry-After: {retry_after} saniye."
                            if retry_after
                            else f"{i}. istekte 429 Too Many Requests alındı."
                        ),
                    )

                # 503 veya Cloudflare 503 de rate limit belirtisi olabilir
                if resp.status_code in (503, 509):
                    trigger_request = i
                    return RateLimitResult(
                        detected=True,
                        requests_sent=i,
                        trigger_request=trigger_request,
                        status_codes=status_codes,
                        details=(
                            f"{i}. istekte {resp.status_code} alındı. "
                            "Muhtemelen rate limiting aktif."
                        ),
                    )

                time.sleep(self.delay)

            except requests.exceptions.ConnectionError:
                logger.warning(
                    f"Bağlantı hatası ({i}. istek) — "
                    "hedef erişilemez durumda olabilir."
                )
                break
            except requests.exceptions.Timeout:
                logger.warning(f"{i}. istek zaman aşımına uğradı.")
                break
            except Exception as e:
                logger.error(f"Rate limit testinde beklenmeyen hata: {e}")
                break

        return RateLimitResult(
            detected=False,
            requests_sent=len(status_codes),
            trigger_request=-1,
            status_codes=status_codes,
            details=(
                f"{len(status_codes)} istek gönderildi, "
                "rate limiting tespit EDİLEMEDİ. "
                "Bu bir güvenlik açığıdır."
            ),
        )

    def test_password_policy(
        self, weak_list: list[str] | None = None
    ) -> PasswordPolicyResult:
        """
        Zayıf parola listesini kullanarak hedefin bunları kabul edip
        etmediğini test eder ve parola politika kalitesini değerlendirir.
        Gerçek girişler denemez — yalnızca politika zayıflıklarını analiz eder.
        """
        if weak_list is None:
            weak_list = WEAK_PASSWORDS

        result = PasswordPolicyResult()
        found_weak: list[str] = []

        for pwd in weak_list:
            try:
                payload = {
                    self.username_field: "policy_test_user",
                    self.password_field: pwd,
                }
                resp = self._session.post(
                    self.target_url,
                    data=payload,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                # 200 veya redirect → zayıf parola kabul edilmiş olabilir
                # (Gerçek login doğrulaması değil, endpoint erişilebilirlik testi)
                if resp.status_code in (200, 302, 301):
                    # Yanıt içeriğinde "hata" veya "başarısız" geçmiyorsa
                    # parola kabul edilmiş sayılır
                    body_lower = resp.text.lower()
                    reject_keywords = [
                        "invalid", "error", "incorrect", "failed",
                        "hata", "yanlış", "başarısız", "geçersiz"
                    ]
                    if not any(kw in body_lower for kw in reject_keywords):
                        found_weak.append(pwd)

                time.sleep(self.delay)

            except Exception as e:
                logger.debug(f"Parola politika testi hatası ({pwd}): {e}")
                continue

        result.weak_passwords_found = found_weak

        # Politika skoru hesapla (100 - ceza puanları)
        score = 100
        if found_weak:
            score -= min(len(found_weak) * 10, 60)  # Her zayıf parola -10
        result.policy_score = max(score, 0)

        result.details = (
            f"{len(weak_list)} zayıf parola test edildi. "
            f"{len(found_weak)} tanesi kabul edildi (veya reddedilmedi). "
            f"Politika skoru: {result.policy_score}/100"
        )
        return result

    def test_account_lockout(
        self,
        username: str = "lockout_test_user",
        max_attempts: int = 10,
    ) -> LockoutResult:
        """
        Ardışık başarısız giriş denemeleri göndererek hesap kilitleme
        (account lockout) mekanizmasının aktif olup olmadığını test eder.
        Lockout 5-6 denemede devreye girmeli; bu sayı güvenlik standardıdır.
        """
        for attempt in range(1, max_attempts + 1):
            try:
                payload = {
                    self.username_field: username,
                    self.password_field: f"wrong_password_{attempt}_xyz!@#",
                }
                resp = self._session.post(
                    self.target_url,
                    data=payload,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                body_lower = resp.text.lower()
                lockout_keywords = [
                    "locked", "kilit", "too many", "çok fazla",
                    "blocked", "engel", "suspend", "askıya",
                    "account locked", "hesabınız kilitlendi",
                ]

                # Lockout tespit koşulları
                if resp.status_code == 423:  # 423 Locked
                    return LockoutResult(
                        lockout_detected=True,
                        failed_attempts_before_lock=attempt,
                        lockout_status_code=423,
                        lockout_message="HTTP 423 Locked",
                        details=(
                            f"{attempt}. denemede hesap kilitleme tespit edildi "
                            f"(HTTP 423). Güvenlik mekanizması çalışıyor."
                        ),
                    )

                if any(kw in body_lower for kw in lockout_keywords):
                    return LockoutResult(
                        lockout_detected=True,
                        failed_attempts_before_lock=attempt,
                        lockout_status_code=resp.status_code,
                        lockout_message=resp.text[:200],
                        details=(
                            f"{attempt}. denemede hesap kilitleme tespit edildi. "
                            "Lockout mesajı yanıt gövdesinde bulundu."
                        ),
                    )

                time.sleep(self.delay)

            except requests.exceptions.ConnectionError:
                # Bağlantı kesilmesi de lockout belirtisi olabilir
                return LockoutResult(
                    lockout_detected=True,
                    failed_attempts_before_lock=attempt,
                    lockout_message="Bağlantı kesildi (muhtemelen IP engellendi)",
                    details=(
                        f"{attempt}. denemede bağlantı kesildi. "
                        "IP tabanlı engelleme uygulanıyor olabilir."
                    ),
                )
            except Exception as e:
                logger.error(f"Lockout testi hatası ({attempt}. deneme): {e}")
                break

        return LockoutResult(
            lockout_detected=False,
            failed_attempts_before_lock=0,
            details=(
                f"{max_attempts} başarısız denemede hesap kilitleme "
                "tespit EDİLEMEDİ. Bu kritik bir güvenlik açığıdır."
            ),
        )

    # ------------------------------------------------------------------
    # İç Yardımcı Metotlar
    # ------------------------------------------------------------------

    def _evaluate_overall_risk(self, report: CredentialTestReport) -> str:
        """Tüm test sonuçlarına bakarak genel risk seviyesini belirler."""
        risk_score = 0

        if report.rate_limit and not report.rate_limit.detected:
            risk_score += 30   # Rate limit yok → ciddi risk
        if report.password_policy and report.password_policy.weak_passwords_found:
            risk_score += 25   # Zayıf parola kabul ediliyor
        if report.lockout and not report.lockout.lockout_detected:
            risk_score += 40   # Lockout yok → brute-force mümkün

        if risk_score >= 60:
            return "Kritik"
        elif risk_score >= 40:
            return "Yüksek"
        elif risk_score >= 20:
            return "Orta"
        return "Düşük"

    def _generate_summary(self, report: CredentialTestReport) -> str:
        """İnsan tarafından okunabilir özet rapor metni üretir."""
        lines = [
            f"=== CREDENTIAL TESTER RAPORU ===",
            f"Hedef: {report.target_url}",
            "",
        ]

        rl = report.rate_limit
        if rl:
            durum = "✅ AKTİF" if rl.detected else "❌ BULUNAMADI"
            lines.append(f"[Rate Limiting] {durum}")
            lines.append(f"  → {rl.details}")

        pp = report.password_policy
        if pp:
            lines.append(f"[Parola Politikası] Skor: {pp.policy_score}/100")
            if pp.weak_passwords_found:
                lines.append(
                    f"  → Zayıf parolalar kabul edildi: "
                    f"{', '.join(pp.weak_passwords_found[:5])}"
                )
            lines.append(f"  → {pp.details}")

        lo = report.lockout
        if lo:
            durum = (
                f"✅ {lo.failed_attempts_before_lock}. denemede aktif"
                if lo.lockout_detected
                else "❌ BULUNAMADI"
            )
            lines.append(f"[Account Lockout] {durum}")
            lines.append(f"  → {lo.details}")

        lines.append("")
        lines.append(f"Genel Risk Seviyesi: {report.overall_risk}")
        lines.append("=" * 35)
        return "\n".join(lines)
