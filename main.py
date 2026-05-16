# -*- coding: utf-8 -*-
import argparse
import sys
from core import config as Ayarlar
from modules.nmap_integration.scanner import nmap_calistir
from modules.nmap_integration.vulnerability import zafiyet_tara
from reports.reporter import rapor_yaz

# Paket motoru ve analiz modülleri
from modules.packet_engine.pcap_reader import PcapReader
from modules.packet_engine.live_sniffer import LiveSniffer
from modules.packet_engine.traffic_analyzer import TrafficAnalyzer
from reports.traffic_reporter import trafik_raporu_olustur


def ana_menu() -> None:
    while True:
        print("\n" + "=" * 55)
        print("    NETSCANNER: AĞ TRAFİĞİ VE GÜVENLİK ANALİZ PLATFORMU    ")
        print("=" * 55)
        print("[ AKTİF TARAMA MODÜLLERİ (NMAP) ]")
        print("1- Hızlı Tarama (-F) [Top 100 Port]")
        print("2- Cihaz Keşfi (-sn) [Ping Scan]")
        print("3- Servis Versiyon Tespiti (-sV)")
        print("4- İşletim Sistemi Analizi (-O)")
        print("5- Agresif Tarama (-A) [Hepsi Bir Arada]")
        print("6- Zafiyet Taraması (NSE Scripts)")
        print("\n[ TRAFİK ANALİZ MODÜLLERİ (PACKET ENGINE) ]")
        print("7- PCAP Ağ Trafiği Analizi ve Anomali Tespiti")
        print("8- Canlı Ağ İzleme (Live Sniffer) ve Tehdit Algılama")
        print("\n[ WEB ARAYÜZÜ ]")
        print("9- Web Arayüzünü (Dashboard) Başlat")
        print("\n10- Çıkış")
        print("=" * 55)

        secim = input("\nSeçiminiz (1-10): ")
        if secim == "10":
            print("[*] Program kapatılıyor. İyi çalışmalar İrem!")
            break

        # PCAP ve Sniffer Modülleri için IP isteme
        if secim in ["7", "8", "9"]:
            if secim == "7":
                dosya_yolu = input("Analiz edilecek .pcap dosyasının yolu: ")
                if not dosya_yolu:
                    continue
                reader = PcapReader(dosya_yolu)
                if reader.read_pcap():
                    paketler = reader.parse_packets()
                    analyzer = TrafficAnalyzer(paketler)
                    sonuclar = analyzer.analyze()
                    trafik_raporu_olustur("pcap_analiz", sonuclar)
            elif secim == "8":
                print(
                    "\n[*] Canlı Ağ İzleme Başlatılıyor... (Durdurmak için ENTER'a basın)"
                )
                sniffer = LiveSniffer()
                sniffer.start_sniffing()
                input()  # Enter bekler
                sniffer.stop_sniffing()
                paketler = sniffer.get_parsed_packets()
                analyzer = TrafficAnalyzer(paketler)
                sonuclar = analyzer.analyze()
                trafik_raporu_olustur("live_sniff", sonuclar)
            elif secim == "9":
                print(
                    "\n[*] Web Arayüzü Başlatılıyor... Tarayıcınızdan "
                    "http://localhost:8000 adresine gidin. Çıkmak için CTRL+C yapın."
                )
                try:
                    import uvicorn
                    uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=False)
                except ImportError:
                    print("[-] HATA: Web arayüzü bileşenleri bulunamadı.")
            continue

        # Nmap modülleri için IP isteme
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
        description="NetScanner: Gelişmiş Ağ Trafiği ve Güvenlik Analiz Platformu"
    )
    # PCAP okuma argümanı
    parser.add_argument("-p", "--pcap", help="Analiz edilecek .pcap dosyasının yolu")
    parser.add_argument("-t", "--target", help="Hedef IP veya Domain adresi")
    parser.add_argument(
        "--test-nmap",
        action="store_true",
        help="Nmap entegrasyonunu test et (Hızlı Tarama)",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Web arayüzünü (Dashboard) başlatır",
    )

    args = parser.parse_args()

    if len(sys.argv) == 1:
        ana_menu()
    elif args.pcap:
        print(f"[*] {args.pcap} dosyası okunuyor ve analiz ediliyor...")
        reader = PcapReader(args.pcap)
        if reader.read_pcap():
            paketler = reader.parse_packets()
            analyzer = TrafficAnalyzer(paketler)
            sonuclar = analyzer.analyze()
            trafik_raporu_olustur("cli_pcap", sonuclar)
    elif args.test_nmap and args.target:
        print(f"[*] {args.target} için entegrasyon testi başlatılıyor...")
        hiz = Ayarlar.TARAMA_HIZI
        nmap_calistir(["nmap", hiz, "-F", args.target], args.target, "test_tarama")
    elif args.web:
        print(
            "[*] Web Arayüzü Başlatılıyor... "
            "Tarayıcınızdan http://localhost:8000 adresine gidin."
        )
        try:
            import uvicorn
            uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=False)
        except ImportError:
            print("[-] HATA: Web arayüzü bileşenleri bulunamadı.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
