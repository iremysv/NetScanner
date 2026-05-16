# -*- coding: utf-8 -*-
import os
from datetime import datetime
from core import config as Ayarlar


def rapor_yaz(hedef: str, sonuc_metni: str) -> str:
    tarih = datetime.now().strftime("%Y-%m-%d_%H-%M")

    # Klasör kontrolü
    if not os.path.exists(Ayarlar.RAPOR_DIZINI):
        os.makedirs(Ayarlar.RAPOR_DIZINI)

    dosya_adi = os.path.join(Ayarlar.RAPOR_DIZINI, f"rapor_{hedef}_{tarih}.txt")

    with open(dosya_adi, "w", encoding="utf-8") as f:
        f.write("--- NMAP TARAMA RAPORU ---\n")
        f.write(f"Hedef: {hedef}\n")
        f.write(f"Tarih: {tarih}\n")
        f.write("-" * 30 + "\n")
        f.write(sonuc_metni)

    print(f"\n[+] Rapor başarıyla oluşturuldu: {dosya_adi}")
    return dosya_adi
