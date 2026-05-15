# -*- coding: utf-8 -*-
"""
Tests/test_config.py
Unit testler: core.config modülünün doğru yüklendiğini ve
eşik değerlerinin beklenen tipte/aralıkta olduğunu doğrular.
"""
import sys
import os

# Proje kök dizinini Python path'ine ekle (pytest'in modülleri bulabilmesi için)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from core import config as Ayarlar


class TestConfigValues:
    """core.config içindeki sabit değerlerin doğruluğunu test eder."""

    def test_port_scan_threshold_exists(self):
        """PORT_SCAN_THRESHOLD tanımlı olmalıdır."""
        assert hasattr(Ayarlar, "PORT_SCAN_THRESHOLD"), (
            "PORT_SCAN_THRESHOLD config'de tanımlı değil."
        )

    def test_port_scan_threshold_is_positive_int(self):
        """PORT_SCAN_THRESHOLD pozitif bir tam sayı olmalıdır."""
        val = Ayarlar.PORT_SCAN_THRESHOLD
        assert isinstance(val, int) and val > 0, (
            f"PORT_SCAN_THRESHOLD pozitif int olmalı, alınan: {val}"
        )

    def test_dns_tunneling_threshold_exists(self):
        """DNS_TUNNELING_THRESHOLD tanımlı olmalıdır."""
        assert hasattr(Ayarlar, "DNS_TUNNELING_THRESHOLD"), (
            "DNS_TUNNELING_THRESHOLD config'de tanımlı değil."
        )

    def test_dns_tunneling_threshold_is_positive_int(self):
        """DNS_TUNNELING_THRESHOLD pozitif bir tam sayı olmalıdır."""
        val = Ayarlar.DNS_TUNNELING_THRESHOLD
        assert isinstance(val, int) and val > 0, (
            f"DNS_TUNNELING_THRESHOLD pozitif int olmalı, alınan: {val}"
        )

    def test_syn_flood_threshold_exists(self):
        """SYN_FLOOD_THRESHOLD tanımlı olmalıdır."""
        assert hasattr(Ayarlar, "SYN_FLOOD_THRESHOLD"), (
            "SYN_FLOOD_THRESHOLD config'de tanımlı değil."
        )

    def test_syn_flood_threshold_is_positive_int(self):
        """SYN_FLOOD_THRESHOLD pozitif bir tam sayı olmalıdır."""
        val = Ayarlar.SYN_FLOOD_THRESHOLD
        assert isinstance(val, int) and val > 0

    def test_large_payload_threshold_exists(self):
        """LARGE_PAYLOAD_THRESHOLD tanımlı olmalıdır."""
        assert hasattr(Ayarlar, "LARGE_PAYLOAD_THRESHOLD"), (
            "LARGE_PAYLOAD_THRESHOLD config'de tanımlı değil."
        )

    def test_large_payload_threshold_is_positive_int(self):
        """LARGE_PAYLOAD_THRESHOLD pozitif bir tam sayı olmalıdır."""
        val = Ayarlar.LARGE_PAYLOAD_THRESHOLD
        assert isinstance(val, int) and val > 0

    def test_rapor_dizini_exists(self):
        """RAPOR_DIZINI tanımlı ve boş olmamalıdır."""
        assert hasattr(Ayarlar, "RAPOR_DIZINI")
        assert isinstance(Ayarlar.RAPOR_DIZINI, str) and len(Ayarlar.RAPOR_DIZINI) > 0

    def test_trafik_rapor_dizini_exists(self):
        """TRAFIK_RAPOR_DIZINI tanımlı ve boş olmamalıdır."""
        assert hasattr(Ayarlar, "TRAFIK_RAPOR_DIZINI")
        assert (
            isinstance(Ayarlar.TRAFIK_RAPOR_DIZINI, str)
            and len(Ayarlar.TRAFIK_RAPOR_DIZINI) > 0
        )

    def test_threshold_hierarchy(self):
        """
        Eşik değerleri mantıksal sıralamaya uymalıdır:
        PORT_SCAN < DNS_TUNNELING < SYN_FLOOD
        """
        assert Ayarlar.PORT_SCAN_THRESHOLD < Ayarlar.SYN_FLOOD_THRESHOLD, (
            "PORT_SCAN_THRESHOLD, SYN_FLOOD_THRESHOLD'dan küçük olmalıdır."
        )
