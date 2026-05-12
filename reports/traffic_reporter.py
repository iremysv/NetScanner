# -*- coding: utf-8 -*-
import os
import json
from datetime import datetime
from core import config as Ayarlar


def trafik_raporu_olustur(rapor_adi_onek: str, sonuclar: dict) -> None:
    tarih = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dizin = getattr(Ayarlar, "TRAFIK_RAPOR_DIZINI", "taramalar/traffic_reports")

    # Klasör kontrolü
    if not os.path.exists(dizin):
        os.makedirs(dizin)

    dosya_adi_txt = os.path.join(dizin, f"traffic_rapor_{rapor_adi_onek}_{tarih}.txt")
    dosya_adi_json = os.path.join(dizin, f"traffic_rapor_{rapor_adi_onek}_{tarih}.json")

    # 1. JSON Formatında Kaydetme
    with open(dosya_adi_json, "w", encoding="utf-8") as f:
        json.dump(sonuclar, f, indent=4, ensure_ascii=False)

    # 2. İnsan Tarafından Okunabilir TXT Formatında Kaydetme
    with open(dosya_adi_txt, "w", encoding="utf-8") as f:
        f.write("--- NETSCANNER TRAFİK ANALİZ RAPORU ---\n")
        f.write(f"Tarih: {tarih}\n")
        f.write(f"Toplam İncelenen Paket: {sonuclar.get('total_packets', 0)}\n")
        f.write("-" * 40 + "\n\n")

        # Protokol Dağılımı
        f.write("[PROTOKOL DAĞILIMI]\n")
        protokoller = sonuclar.get("protocol_distribution", {})
        for proto, sayi in protokoller.items():
            f.write(f"  - {proto}: {sayi} paket\n")
        f.write("\n")

        # Top Talkers
        f.write("[EN ÇOK TRAFİK ÜRETEN IP'LER (TOP TALKERS)]\n")
        top_talkers = sonuclar.get("top_talkers", {})
        for ip, paket_sayisi in top_talkers.items():
            f.write(f"  - {ip}: {paket_sayisi} paket\n")
        f.write("\n")

        # Anomaliler
        f.write("[TESPİT EDİLEN ANOMALİLER]\n")
        anomaliler = sonuclar.get("anomalies", [])
        if not anomaliler:
            f.write("  - Herhangi bir anomali tespit edilmedi.\n")
        else:
            for anomali in anomaliler:
                f.write(f"  ! DİKKAT [{anomali.get('type')}]: IP: {anomali.get('source_ip')} -> {anomali.get('details')}\n")
        f.write("\n" + "-" * 40 + "\n")

    print(f"\n[+] Trafik analiz raporu oluşturuldu:\n    TXT: {dosya_adi_txt}\n    JSON: {dosya_adi_json}")
