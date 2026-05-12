# -*- coding: utf-8 -*-
import argparse
import sys
from core import config as Ayarlar
from modules.nmap_integration.scanner import nmap_calistir
from modules.nmap_integration.vulnerability import zafiyet_tara
from reports.reporter import rapor_yaz


def ana_menu() -> None:
    while True:
        print("\n" + "=" * 45)
        print("      SIZMA TESTİ VE ANALİZ PANELİ      ")
        print("=" * 45)
        print("1- Hızlı Tarama (-F) [Top 100 Port]")
        print("2- Cihaz Keşfi (-sn) [Ping Scan]")
        print("3- Servis Versiyon Tespiti (-sV)")
        print("4- İşletim Sistemi Analizi (-O)")
        print("5- Agresif Tarama (-A) [Hepsi Bir Arada]")
        print("6- Zafiyet Taraması (NSE Scripts)")
        print("7- Çıkış")
        print("=" * 45)
        secim = input("\nSeçiminiz (1-7): ")
        if secim == "7":
            print("[*] Program kapatılıyor. İyi çalışmalar İrem!")
            break
        hedef = input("Hedef IP veya Domain: ")
        if not hedef:
            continue

        hiz = Ayarlar.TARAMA_HIZI

        if secim == "1":
            nmap_calistir(["nmap", hiz, "-F", hedef], hedef, "hizli_tarama")
        elif secim == "2":
            nmap_calistir(["nmap", hiz, "-sn", hedef], hedef, "cihaz_kesfi")
        elif secim == "3":
            nmap_calistir(["nmap", hiz, "-sV", hedef], hedef, "servis_analizi")
        elif secim == "4":
            nmap_calistir(["sudo", "nmap", hiz, "-O", hedef], hedef, "os_analizi")
        elif secim == "5":
            nmap_calistir(["sudo", "nmap", hiz, "-A", hedef], hedef, "agresif_tarama")
        elif secim == "6":
            sonuc = zafiyet_tara(hedef)
            rapor_yaz(f"{hedef}_zafiyet", sonuc)
            print(sonuc)
        else:
            print("[-] Geçersiz seçim.")


def main():
    parser = argparse.ArgumentParser(
        description="NetScanner: Nmap Entegrasyonlu PCAP Analiz ve Anomali Tespit Motoru"
    )
    # PCAP okuma argümanı
    parser.add_argument("-p", "--pcap", help="Analiz edilecek .pcap dosyasının yolu")
    parser.add_argument("-t", "--target", help="Hedef IP veya Domain adresi")
    parser.add_argument("--test-nmap", action="store_true", help="Nmap entegrasyonunu test et (Hızlı Tarama)")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        ana_menu()
    elif args.pcap:
        print(f"[*] {args.pcap} dosyası okunuyor ve analiz ediliyor...")
        from modules.packet_engine.pcap_reader import PcapReader
        reader = PcapReader(args.pcap)
        if reader.read_pcap():
            paketler = reader.parse_packets()
            print("\n[*] Parse Edilen İlk 5 Paket:")
            for p in paketler[:5]:
                print(p)
    elif args.test_nmap and args.target:
        print(f"[*] {args.target} için entegrasyon testi başlatılıyor...")
        hiz = Ayarlar.TARAMA_HIZI
        nmap_calistir(["nmap", hiz, "-F", args.target], args.target, "test_tarama")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
