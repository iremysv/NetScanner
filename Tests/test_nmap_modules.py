# -*- coding: utf-8 -*-
"""
Tests/test_nmap_modules.py
Unit testler: modules.nmap_integration.analyzer,
modules.nmap_integration.vulnerability ve
modules.nmap_integration.scanner modüllerini doğrular.
Gerçek ağ/nmap çağrıları monkeypatch ile devre dışı bırakılır.
"""
import os
import sys
import subprocess

import pytest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from modules.nmap_integration.analyzer import analiz_et  # noqa: E402
from modules.nmap_integration.vulnerability import (  # noqa: E402
    zafiyet_tara,
)
from modules.nmap_integration.scanner import nmap_calistir  # noqa: E402


# ===========================================================================
# analiz_et (nmap_integration.analyzer) testleri
# ===========================================================================


class TestAnalyzEt:
    """analiz_et fonksiyonunun port listesiyle doğru çalıştığını doğrular."""

    def test_known_port_80_does_not_raise(self, capsys):
        """Port 80 ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et(["80"])
        # Herhangi bir hata olmadan tamamlanırsa test geçer

    def test_known_port_443_does_not_raise(self, capsys):
        """Port 443 ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et(["443"])

    def test_known_port_22_does_not_raise(self, capsys):
        """Port 22 (SSH) ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et(["22"])

    def test_known_port_21_does_not_raise(self, capsys):
        """Port 21 (FTP) ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et(["21"])

    def test_known_port_445_does_not_raise(self, capsys):
        """Port 445 (SMB) ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et(["445"])

    def test_known_port_3389_does_not_raise(self, capsys):
        """Port 3389 (RDP) ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et(["3389"])

    def test_empty_port_list_does_not_raise(self, capsys):
        """Boş liste ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et([])

    def test_unknown_port_does_not_raise(self, capsys):
        """Bilinmeyen port ile çağrılınca exception fırlatılmamalıdır."""
        analiz_et(["9999"])

    def test_output_contains_header(self, capsys):
        """Analiz çıktısı başlık içermelidir."""
        analiz_et(["80"])
        captured = capsys.readouterr()
        assert "GÜVENLİK" in captured.out or "=" in captured.out

    def test_output_http_mention_for_port_80(self, capsys):
        """Port 80 için HTTP ile ilgili bilgi yazdırılmalıdır."""
        analiz_et(["80"])
        captured = capsys.readouterr()
        assert "HTTP" in captured.out

    def test_output_ssh_mention_for_port_22(self, capsys):
        """Port 22 için SSH ile ilgili bilgi yazdırılmalıdır."""
        analiz_et(["22"])
        captured = capsys.readouterr()
        assert "SSH" in captured.out

    def test_output_ftp_mention_for_port_21(self, capsys):
        """Port 21 için FTP ile ilgili bilgi yazdırılmalıdır."""
        analiz_et(["21"])
        captured = capsys.readouterr()
        assert "FTP" in captured.out

    def test_output_smb_mention_for_port_445(self, capsys):
        """Port 445 için SMB ile ilgili bilgi yazdırılmalıdır."""
        analiz_et(["445"])
        captured = capsys.readouterr()
        assert "SMB" in captured.out

    def test_output_rdp_mention_for_port_3389(self, capsys):
        """Port 3389 için RDP ile ilgili bilgi yazdırılmalıdır."""
        analiz_et(["3389"])
        captured = capsys.readouterr()
        assert "RDP" in captured.out

    def test_unknown_port_prints_not_found_msg(self, capsys):
        """Bilinmeyen port için 'öneri bulunamadı' mesajı yazılmalıdır."""
        analiz_et(["9999"])
        captured = capsys.readouterr()
        assert "bulunamadı" in captured.out

    def test_empty_list_prints_not_found_msg(self, capsys):
        """Boş liste için de 'öneri bulunamadı' mesajı yazılmalıdır."""
        analiz_et([])
        captured = capsys.readouterr()
        assert "bulunamadı" in captured.out

    def test_multiple_ports_all_printed(self, capsys):
        """Birden fazla port girilince hepsi için çıktı üretilmelidir."""
        analiz_et(["80", "22", "443"])
        captured = capsys.readouterr()
        assert "HTTP" in captured.out
        assert "SSH" in captured.out
        assert "HTTPS" in captured.out

    def test_returns_none(self):
        """Fonksiyon None döndürmelidir (side-effect fonksiyon)."""
        result = analiz_et(["80"])
        assert result is None

    def test_integer_port_treated_as_string(self, capsys):
        """Integer port değerleri string'e çevrilerek işlenmelidir."""
        # Fonksiyon str(port) yapıyor, bu yüzden int de kabul edilmeli
        analiz_et([80])
        captured = capsys.readouterr()
        assert "HTTP" in captured.out


# ===========================================================================
# zafiyet_tara (nmap_integration.vulnerability) testleri
# ===========================================================================


class TestZafiyetTara:
    """zafiyet_tara fonksiyonunun dönüş değeri ve hata yönetimini doğrular."""

    def test_returns_string(self, monkeypatch):
        """Fonksiyon her durumda string döndürmelidir."""
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="nmap output", stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)
        result = zafiyet_tara("192.168.1.1")
        assert isinstance(result, str)

    def test_returns_stdout_on_success(self, monkeypatch):
        """Başarılı taramada nmap stdout döndürülmelidir."""
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="PORT   STATE SERVICE\n80/tcp open  http",
            stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)
        result = zafiyet_tara("192.168.1.1")
        assert "PORT" in result

    def test_returns_error_string_on_failure(self, monkeypatch):
        """subprocess hatası olunca hata mesajı string olarak döner."""
        def mock_run(*args, **kwargs):
            raise subprocess.CalledProcessError(1, "nmap")

        monkeypatch.setattr(subprocess, "run", mock_run)
        result = zafiyet_tara("192.168.1.1")
        assert "hata" in result.lower() or "error" in result.lower()

    def test_returns_error_on_file_not_found(self, monkeypatch):
        """nmap kurulu değilse hata mesajı döndürülmelidir."""
        def mock_run(*args, **kwargs):
            raise FileNotFoundError("nmap not found")

        monkeypatch.setattr(subprocess, "run", mock_run)
        result = zafiyet_tara("192.168.1.1")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_includes_target_in_command(self, monkeypatch):
        """Nmap komutu hedef IP adresini içermelidir."""
        called_with = {}

        def mock_run(cmd, *args, **kwargs):
            called_with["cmd"] = cmd
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="ok", stderr=""
            )

        monkeypatch.setattr(subprocess, "run", mock_run)
        zafiyet_tara("10.0.0.99")
        assert "10.0.0.99" in called_with["cmd"]

    def test_uses_vuln_script(self, monkeypatch):
        """Komut, NSE vuln scriptini içermelidir."""
        called_with = {}

        def mock_run(cmd, *args, **kwargs):
            called_with["cmd"] = cmd
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="ok", stderr=""
            )

        monkeypatch.setattr(subprocess, "run", mock_run)
        zafiyet_tara("10.0.0.1")
        cmd_str = " ".join(called_with["cmd"])
        assert "vuln" in cmd_str


# ===========================================================================
# nmap_calistir (nmap_integration.scanner) testleri
# ===========================================================================


class TestNmapCalistir:
    """nmap_calistir fonksiyonunun dönüş değeri ve hata yönetimini doğrular."""

    def _mock_run_success(self, monkeypatch, tmp_path, stdout_text):
        """Başarılı subprocess.run ve rapor dizini mocklayan yardımcı."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))

        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout_text, stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

    def test_returns_tuple_on_success(self, monkeypatch, tmp_path):
        """Başarılı taramada (str, str) tuple döndürmelidir."""
        self._mock_run_success(monkeypatch, tmp_path, "nmap output")
        result = nmap_calistir(["nmap", "-F", "127.0.0.1"], "127.0.0.1", "test")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)
        assert isinstance(result[1], str)

    def test_returns_stdout_content(self, monkeypatch, tmp_path):
        """Döndürülen tuple'ın ilk elemanı nmap stdout'u olmalıdır."""
        self._mock_run_success(monkeypatch, tmp_path, "PORT_SCAN_RESULT")
        stdout, _ = nmap_calistir(
            ["nmap", "-F", "127.0.0.1"], "127.0.0.1", "test"
        )
        assert "PORT_SCAN_RESULT" in stdout

    def test_creates_report_file(self, monkeypatch, tmp_path):
        """Tarama sonucu bir rapor dosyası oluşturmalıdır."""
        self._mock_run_success(monkeypatch, tmp_path, "output")
        _, rapor_yolu = nmap_calistir(
            ["nmap", "-F", "127.0.0.1"], "127.0.0.1", "test"
        )
        assert os.path.isfile(rapor_yolu)

    def test_returns_none_tuple_on_failure(self, monkeypatch, tmp_path):
        """subprocess hatası durumunda (None, None) döndürmelidir."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))

        def mock_fail(*args, **kwargs):
            raise subprocess.CalledProcessError(1, "nmap", stderr="err")

        monkeypatch.setattr(subprocess, "run", mock_fail)
        result = nmap_calistir(
            ["nmap", "-F", "127.0.0.1"], "127.0.0.1", "test"
        )
        assert result == (None, None)

    def test_returns_none_on_unexpected_error(self, monkeypatch, tmp_path):
        """Beklenmedik exception durumunda (None, None) döndürmelidir."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))

        def mock_crash(*args, **kwargs):
            raise RuntimeError("Unexpected")

        monkeypatch.setattr(subprocess, "run", mock_crash)
        result = nmap_calistir(
            ["nmap", "-F", "127.0.0.1"], "127.0.0.1", "test"
        )
        assert result == (None, None)

    def test_open_port_triggers_analyzer(self, monkeypatch, tmp_path, capsys):
        """Açık port tespit edilince analiz motoru tetiklenmelidir."""
        stdout_with_ports = (
            "80/tcp open http\n"
            "22/tcp open ssh\n"
        )
        self._mock_run_success(monkeypatch, tmp_path, stdout_with_ports)
        nmap_calistir(["nmap", "-F", "127.0.0.1"], "127.0.0.1", "test")
        captured = capsys.readouterr()
        # analiz_et çağrıldıysa HTTP veya SSH çıktısı olmalı
        assert "HTTP" in captured.out or "SSH" in captured.out

    def test_no_open_ports_skips_analyzer(self, monkeypatch, tmp_path, capsys):
        """Açık port yoksa analiz motoru çıktısı olmamalıdır."""
        self._mock_run_success(monkeypatch, tmp_path, "No open ports found.")
        nmap_calistir(["nmap", "-F", "127.0.0.1"], "127.0.0.1", "test")
        captured = capsys.readouterr()
        # analiz_et çağrılmadıysa GÜVENLİK başlığı görünmemeli
        assert "GÜVENLİK ANALİZİ" not in captured.out
