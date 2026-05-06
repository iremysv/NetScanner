# -*- coding: utf-8 -*-
import argparse
import sys
import os
import Ayarlar
from ScannerTool import nmap_calistir
from ZafiyetTarayici import zafiyet_tara
from RaporOlusturucu import rapor_yaz


def main():
    parser = argparse.ArgumentParser(
        description="NmapScannerTool: Gelişmiş Ağ Analiz ve Güvenlik Çözümü"
    )

    # Tarama Modları
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-q",
        "--quick",
        action="store_true",
        help="Hızlı Tarama (-F) [En yaygın 100 port]",
    )
    group.add_argument(
        "-s", "--discovery", action="store_true", help="Cihaz Keşfi (-sn) [Ping Scan]"
    )
    group.add_argument(
        "-v", "--version", action="store_true", help="Servis Versiyon Tespiti (-sV)"
    )
    group.add_argument(
        "-o", "--os", action="store_true", help="İşletim Sistemi Analizi (-O)"
    )
    group.add_argument(
        "-a",
        "--aggressive",
        action="store_true",
        help="Agresif Tarama (-A) [Hepsi Bir Arada]",
    )
    group.add_argument(
        "-x", "--vuln", action="store_true", help="Zafiyet Taraması (NSE Scripts)"
    )

    # Hedef Parametresi
    parser.add_argument(
        "-t", "--target", required=True, help="Hedef IP veya Domain adresi"
    )

    args = parser.parse_args()

    hedef = args.target
    hiz = Ayarlar.TARAMA_HIZI

    print(f"\n[+] Hedef: {hedef} üzerinde tarama başlatılıyor...")

    if args.quick:
        nmap_calistir(["nmap", hiz, "-F", hedef], hedef, "hizli_tarama")
    elif args.discovery:
        nmap_calistir(["nmap", hiz, "-sn", hedef], hedef, "cihaz_kesfi")
    elif args.version:
        nmap_calistir(["nmap", hiz, "-sV", hedef], hedef, "servis_analizi")
    elif args.os:
        nmap_calistir(["sudo", "nmap", hiz, "-O", hedef], hedef, "os_analizi")
    elif args.aggressive:
        nmap_calistir(["sudo", "nmap", hiz, "-A", hedef], hedef, "agresif_tarama")
    elif args.vuln:
        sonuc = zafiyet_tara(hedef)
        rapor_yaz(f"{hedef}_zafiyet", sonuc)
        print(sonuc)


if __name__ == "__main__":
    main()
