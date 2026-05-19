# -*- coding: utf-8 -*-
"""
Tests/test_reporter.py
Unit testler: reports.reporter ve reports.traffic_reporter modüllerinin
dosya oluşturma, içerik doğruluğu ve hata toleransını doğrular.
"""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from reports.reporter import rapor_yaz  # noqa: E402
from reports.traffic_reporter import (  # noqa: E402
    trafik_raporu_olustur,
    _generate_html,
)


# ---------------------------------------------------------------------------
# Yardımcı veri
# ---------------------------------------------------------------------------

SAMPLE_SONUCLAR = {
    "total_packets": 42,
    "protocol_distribution": {"TCP": 30, "UDP": 10, "Other": 2},
    "top_talkers": [
        {"ip": "192.168.1.1", "count": 20, "location": "Local"},
        {"ip": "8.8.8.8", "count": 10, "location": "Google/US"},
    ],
    "anomalies": [
        {
            "type": "PORT_SCAN",
            "source_ip": "10.0.0.5",
            "details": "50 farklı porta erişim",
        }
    ],
}

EMPTY_SONUCLAR: dict = {
    "total_packets": 0,
    "protocol_distribution": {},
    "top_talkers": [],
    "anomalies": [],
}


# ===========================================================================
# rapor_yaz (reports.reporter) testleri
# ===========================================================================


class TestRaporYaz:
    """rapor_yaz fonksiyonunun davranışını doğrular."""

    def test_returns_file_path_string(self, tmp_path, monkeypatch):
        """Fonksiyon gerçek bir dosya yolu döndürmelidir."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))
        result = rapor_yaz("test_hedef", "Test sonuç metni")
        assert isinstance(result, str)

    def test_file_is_created(self, tmp_path, monkeypatch):
        """Rapor dosyası disk üzerinde oluşturulmalıdır."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))
        path = rapor_yaz("test_hedef", "İçerik")
        assert os.path.isfile(path)

    def test_file_contains_header(self, tmp_path, monkeypatch):
        """Oluşturulan dosya NMAP başlığını içermelidir."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))
        path = rapor_yaz("hedef_ip", "sonuc_data")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "NMAP TARAMA RAPORU" in content

    def test_file_contains_target(self, tmp_path, monkeypatch):
        """Rapor dosyası hedef IP/domain bilgisini içermelidir."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))
        path = rapor_yaz("192.168.1.100", "nmap output")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "192.168.1.100" in content

    def test_file_contains_result_text(self, tmp_path, monkeypatch):
        """Rapor dosyası sonuç metnini içermelidir."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))
        path = rapor_yaz("host", "ÖZEL_SONUC_STRING")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "ÖZEL_SONUC_STRING" in content

    def test_creates_directory_if_missing(self, tmp_path, monkeypatch):
        """RAPOR_DIZINI yoksa otomatik oluşturulmalıdır."""
        import core.config as Ayarlar

        new_dir = str(tmp_path / "yeni_klasor")
        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", new_dir)
        rapor_yaz("host", "veri")
        assert os.path.isdir(new_dir)

    def test_filename_contains_target(self, tmp_path, monkeypatch):
        """Dosya adı hedef bilgisini içermelidir."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "RAPOR_DIZINI", str(tmp_path))
        path = rapor_yaz("unique_host_xyz", "veri")
        assert "unique_host_xyz" in os.path.basename(path)


# ===========================================================================
# trafik_raporu_olustur (reports.traffic_reporter) testleri
# ===========================================================================


class TestTrafikRaporuOlustur:
    """trafik_raporu_olustur fonksiyonunun üç format çıkışını doğrular."""

    def _run_and_collect(self, tmp_path, monkeypatch, sonuclar):
        """Yardımcı: geçici dizine rapor oluştur, dosya yollarını döndür."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "TRAFIK_RAPOR_DIZINI", str(tmp_path))
        trafik_raporu_olustur("test_onek", sonuclar)
        files = list(tmp_path.iterdir())
        return {f.suffix: f for f in files}

    def test_creates_three_files(self, tmp_path, monkeypatch):
        """JSON, TXT ve HTML olmak üzere 3 dosya oluşturulmalıdır."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        assert ".json" in files
        assert ".txt" in files
        assert ".html" in files

    def test_json_file_is_valid(self, tmp_path, monkeypatch):
        """JSON dosyası parse edilebilir geçerli bir JSON olmalıdır."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        with open(files[".json"], encoding="utf-8") as f:
            data = json.load(f)
        assert data["total_packets"] == 42

    def test_json_contains_all_keys(self, tmp_path, monkeypatch):
        """JSON tüm analiz anahtarlarını içermelidir."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        with open(files[".json"], encoding="utf-8") as f:
            data = json.load(f)
        for key in ("total_packets", "protocol_distribution",
                    "top_talkers", "anomalies"):
            assert key in data

    def test_txt_contains_header(self, tmp_path, monkeypatch):
        """TXT dosyası rapor başlığı içermelidir."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        with open(files[".txt"], encoding="utf-8") as f:
            content = f.read()
        assert "NETSCANNER" in content

    def test_txt_contains_packet_count(self, tmp_path, monkeypatch):
        """TXT dosyası toplam paket sayısını içermelidir."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        with open(files[".txt"], encoding="utf-8") as f:
            content = f.read()
        assert "42" in content

    def test_txt_contains_anomaly(self, tmp_path, monkeypatch):
        """TXT dosyası tespit edilen anomaliyi içermelidir."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        with open(files[".txt"], encoding="utf-8") as f:
            content = f.read()
        assert "PORT_SCAN" in content

    def test_txt_no_anomaly_message(self, tmp_path, monkeypatch):
        """Anomali yoksa TXT'de 'tespit edilmedi' yazmalıdır."""
        files = self._run_and_collect(tmp_path, monkeypatch, EMPTY_SONUCLAR)
        with open(files[".txt"], encoding="utf-8") as f:
            content = f.read()
        assert "tespit edilmedi" in content

    def test_html_is_valid_document(self, tmp_path, monkeypatch):
        """HTML dosyası DOCTYPE ve html etiketlerini içermelidir."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        with open(files[".html"], encoding="utf-8") as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_html_contains_anomaly_alert(self, tmp_path, monkeypatch):
        """HTML anomali için uyarı kutusu içermelidir."""
        files = self._run_and_collect(tmp_path, monkeypatch, SAMPLE_SONUCLAR)
        with open(files[".html"], encoding="utf-8") as f:
            content = f.read()
        assert "PORT_SCAN" in content
        assert "10.0.0.5" in content

    def test_empty_sonuclar_does_not_raise(self, tmp_path, monkeypatch):
        """Boş analiz verisiyle çağrılınca exception fırlatılmamalıdır."""
        import core.config as Ayarlar

        monkeypatch.setattr(Ayarlar, "TRAFIK_RAPOR_DIZINI", str(tmp_path))
        try:
            trafik_raporu_olustur("empty_test", EMPTY_SONUCLAR)
        except Exception as exc:
            pytest.fail(f"Beklenmedik hata: {exc}")

    def test_creates_directory_if_missing(self, tmp_path, monkeypatch):
        """TRAFIK_RAPOR_DIZINI yoksa otomatik oluşturulmalıdır."""
        import core.config as Ayarlar

        new_dir = str(tmp_path / "trafik_yeni")
        monkeypatch.setattr(Ayarlar, "TRAFIK_RAPOR_DIZINI", new_dir)
        trafik_raporu_olustur("dir_test", SAMPLE_SONUCLAR)
        assert os.path.isdir(new_dir)


# ===========================================================================
# _generate_html iç fonksiyon testleri
# ===========================================================================


class TestGenerateHtml:
    """_generate_html yardımcı fonksiyonunun içeriğini doğrular."""

    def test_returns_string(self):
        """Fonksiyon bir string döndürmelidir."""
        result = _generate_html("2026-01-01", SAMPLE_SONUCLAR)
        assert isinstance(result, str)

    def test_contains_doctype(self):
        """HTML çıktısı DOCTYPE içermelidir."""
        result = _generate_html("2026-01-01", SAMPLE_SONUCLAR)
        assert "<!DOCTYPE html>" in result

    def test_contains_tarih(self):
        """HTML çıktısı tarih bilgisini içermelidir."""
        result = _generate_html("2026-05-19_12-00-00", SAMPLE_SONUCLAR)
        assert "2026-05-19_12-00-00" in result

    def test_contains_protocol_names(self):
        """Protokol adları HTML içinde görünmelidir."""
        result = _generate_html("2026-01-01", SAMPLE_SONUCLAR)
        assert "TCP" in result
        assert "UDP" in result

    def test_contains_talker_ip(self):
        """Top talker IP adresleri HTML'de yer almalıdır."""
        result = _generate_html("2026-01-01", SAMPLE_SONUCLAR)
        assert "192.168.1.1" in result
        assert "8.8.8.8" in result

    def test_no_anomaly_message_when_empty(self):
        """Anomali yoksa HTML yeşil renkte mesaj içermelidir."""
        result = _generate_html("2026-01-01", EMPTY_SONUCLAR)
        assert "tespit edilmedi" in result

    def test_anomaly_present_shows_alert(self):
        """Anomali varsa alert sınıflı div oluşturulmalıdır."""
        result = _generate_html("2026-01-01", SAMPLE_SONUCLAR)
        assert "class='alert'" in result
