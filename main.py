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
    
    # İleride PCAP okuma ve Canlı dinleme argümanları buraya eklenecek
    parser.add_argument("-t", "--target", help="Hedef IP veya Domain adresi")
    parser.add_argument("--test-nmap", action="store_true", help="Nmap entegrasyonunu test et (Hızlı Tarama)")
    
    args = parser.parse_args()

    if args.test_nmap and args.target:
        print(f"[*] {args.target} için entegrasyon testi başlatılıyor...")
        hiz = Ayarlar.TARAMA_HIZI
        nmap_calistir(["nmap", hiz, "-F", args.target], args.target, "test_tarama")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
