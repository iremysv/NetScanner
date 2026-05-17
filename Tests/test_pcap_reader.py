# -*- coding: utf-8 -*-
"""
Tests/test_pcap_reader.py
Unit testler: PcapReader sınıfının PCAP okuma, parse etme ve
hata yönetimi davranışlarını doğrular.
dummy.pcap → proje kök dizinindeki gerçek test dosyası kullanılır.
"""
import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

import pytest  # noqa: E402
from modules.packet_engine.pcap_reader import PcapReader  # noqa: E402

# Proje kökündeki dummy.pcap dosyasının mutlak yolu
DUMMY_PCAP = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "dummy.pcap")
)
NONEXISTENT_PCAP = "/tmp/bu_dosya_kesinlikle_yoktur_12345.pcap"


class TestPcapReaderInit:
    """PcapReader başlatma davranışını test eder."""

    def test_reader_stores_file_path(self):
        """PcapReader, verilen dosya yolunu saklamalıdır."""
        reader = PcapReader(DUMMY_PCAP)
        assert reader.file_path == DUMMY_PCAP

    def test_initial_parsed_data_empty(self):
        """Başlangıçta parsed_data boş liste olmalıdır."""
        reader = PcapReader(DUMMY_PCAP)
        assert reader.parsed_data == []

    def test_initial_read_success_false(self):
        """Başlangıçta _read_success False olmalıdır."""
        reader = PcapReader(DUMMY_PCAP)
        assert reader._read_success is False


class TestPcapReaderReadPcap:
    """read_pcap() metodunun davranışını test eder."""

    def test_nonexistent_file_returns_false(self):
        """Var olmayan bir dosya için read_pcap() False döndürmeli."""
        reader = PcapReader(NONEXISTENT_PCAP)
        result = reader.read_pcap()
        assert result is False, (
            f"Var olmayan dosya için True döndü: {result}"
        )

    def test_nonexistent_file_leaves_parsed_data_empty(self):
        """Var olmayan dosya sonrası parsed_data boş kalmalıdır."""
        reader = PcapReader(NONEXISTENT_PCAP)
        reader.read_pcap()
        assert reader.parsed_data == []

    def test_dummy_pcap_read_returns_true(self):
        """dummy.pcap başarıyla okunduğunda True döndürmeli."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        result = reader.read_pcap()
        assert result is True, "dummy.pcap okunabilmeli ve True dönmeli."

    def test_dummy_pcap_sets_read_success(self):
        """Başarılı okuma sonrası _read_success True olmalıdır."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        reader.read_pcap()
        assert reader._read_success is True


class TestPcapReaderParsePackets:
    """parse_packets() metodunun davranışını test eder."""

    def test_parse_without_read_returns_empty(self):
        """read_pcap() çağrılmadan parse_packets() boş liste döndürmeli."""
        reader = PcapReader(DUMMY_PCAP)
        packets = reader.parse_packets()
        assert packets == [], (
            f"read_pcap() olmadan boş liste beklendi, alınan: {packets}"
        )

    def test_parse_after_read_returns_list(self):
        """Başarılı read_pcap() sonrası parse_packets() liste döndürmeli."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        reader.read_pcap()
        packets = reader.parse_packets()
        assert isinstance(packets, list), (
            f"parse_packets() liste döndürmeli, alınan tip: {type(packets)}"
        )

    def test_parsed_packets_not_empty(self):
        """dummy.pcap içinde en az bir geçerli paket olmalıdır."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        reader.read_pcap()
        packets = reader.parse_packets()
        assert len(packets) > 0, (
            "dummy.pcap'tan en az 1 paket parse edilmeli."
        )

    def test_parsed_packet_has_required_fields(self):
        """Her parse edilmiş paket gerekli anahtarları içermeli."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        reader.read_pcap()
        packets = reader.parse_packets()

        required_fields = {
            "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "length", "flags",
        }
        for i, pkt in enumerate(packets[:5]):  # İlk 5 paketi kontrol et
            missing = required_fields - set(pkt.keys())
            assert not missing, (
                f"Paket {i} şu alanlardan yoksun: {missing}"
            )

    def test_parsed_packet_src_ip_is_string(self):
        """Her paketin src_ip alanı string olmalıdır."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        reader.read_pcap()
        packets = reader.parse_packets()
        for pkt in packets[:10]:
            assert isinstance(pkt["src_ip"], str), (
                f"src_ip string olmalı, alınan: {type(pkt['src_ip'])}"
            )

    def test_parsed_packet_length_positive(self):
        """Her paketin uzunluğu pozitif olmalıdır."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        reader.read_pcap()
        packets = reader.parse_packets()
        for pkt in packets[:10]:
            assert pkt["length"] > 0, (
                f"Paket uzunluğu pozitif olmalı, alınan: {pkt['length']}"
            )

    def test_parse_packets_equals_get_packets(self):
        """parse_packets() ve get_packets() aynı sonucu döndürmeli."""
        if not os.path.exists(DUMMY_PCAP):
            pytest.skip("dummy.pcap bulunamadı, test atlandı.")
        reader = PcapReader(DUMMY_PCAP)
        reader.read_pcap()
        assert reader.parse_packets() == reader.get_packets()
