# -*- coding: utf-8 -*-
import argparse
from core import config as Ayarlar
from modules.nmap_integration.scanner import nmap_calistir
from modules.nmap_integration.vulnerability import zafiyet_tara
from reports.reporter import rapor_yaz

def main():
    parser = argparse.ArgumentParser(
        description="NetScanner: Nmap Entegrasyonlu PCAP Analiz ve Anomali Tespit Motoru"
    )
    
    # PCAP okuma argümanı
    parser.add_argument("-p", "--pcap", help="Analiz edilecek .pcap dosyasının yolu")
    parser.add_argument("-t", "--target", help="Hedef IP veya Domain adresi")
    parser.add_argument("--test-nmap", action="store_true", help="Nmap entegrasyonunu test et (Hızlı Tarama)")
    
    args = parser.parse_args()

    if args.pcap:
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
