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
from reports.markdown_reporter import markdown_guvenlik_raporu_olustur

# Final Proje — Yeni Modüller
from modules.vuln_scanner.full_scanner import FullVulnerabilityScanner
from modules.credential_tester.tester import CredentialTester
from modules.api_scanner.scanner import APISecurityScanner


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
        print("\n[ FİNAL PROJE — YENİ MODÜLLER ]")
        print("9-  Full Vulnerability Scanner (Otomatik Zincir)")
        print("10- Credential Tester (Rate Limit / Lockout / Parola)")
        print("11- API Security Scanner (OWASP API Top 10 + BOLA)")
        print("\n[ WEB ARAYÜZÜ ]")
        print("12- Web Arayüzünü (Dashboard) Başlat")
        print("\n0 - Çıkış")
        print("=" * 55)

        secim = input("\nSeçiminiz (0-12): ")
        if secim == "0":
            print("[*] Program kapatılıyor. İyi çalışmalar İrem!")
            break

        # PCAP ve Sniffer Modülleri için IP isteme
        if secim in ["7", "8", "9", "10", "11", "12"]:
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
                    markdown_guvenlik_raporu_olustur(
                        hedef=dosya_yolu,
                        trafik_sonuclar=sonuclar,
                        connection_map=sonuclar.get("connection_map"),
                    )
            elif secim == "8":
                print(
                    "\n[*] Canlı Ağ İzleme Başlatılıyor..."
                    " (Durdurmak için ENTER'a basın)"
                )
                sniffer = LiveSniffer()
                sniffer.start_sniffing()
                input()  # Enter bekler
                sniffer.stop_sniffing()
                paketler = sniffer.get_parsed_packets()
                analyzer = TrafficAnalyzer(paketler)
                sonuclar = analyzer.analyze()
                trafik_raporu_olustur("live_sniff", sonuclar)
                markdown_guvenlik_raporu_olustur(
                    hedef="Canli_Ag",
                    trafik_sonuclar=sonuclar,
                    connection_map=sonuclar.get("connection_map"),
                )
            elif secim == "9":
                # Full Vulnerability Scanner
                hedef_full = input("Hedef IP veya Domain: ")
                if not hedef_full:
                    continue
                pcap_yolu = input(
                    "PCAP dosyası yolu (opsiyonel, boş bırakılabilir): "
                ).strip()
                api_url = input(
                    "API base URL (opsiyonel, örn: http://hedef/api): "
                ).strip()
                login_url = input(
                    "Login URL (opsiyonel, credential testi için): "
                ).strip()
                scanner = FullVulnerabilityScanner(
                    target=hedef_full,
                    pcap_file=pcap_yolu or None,
                    api_base_url=api_url or None,
                    login_url=login_url or None,
                )
                scanner.run_full_scan()

            elif secim == "10":
                # Credential Tester
                login_url_ct = input(
                    "Login endpoint URL (örn: http://hedef/login): "
                )
                if not login_url_ct:
                    continue
                tester = CredentialTester(
                    target_url=login_url_ct,
                    delay_between_requests=0.3,
                )
                rapor = tester.run_all_tests()
                print(rapor.summary)

            elif secim == "11":
                # API Security Scanner
                api_base = input(
                    "API base URL (örn: http://hedef:8080/api): "
                )
                if not api_base:
                    continue
                openapi_url = input(
                    "OpenAPI/Swagger spec URL (opsiyonel): "
                ).strip() or None
                api_scanner = APISecurityScanner(
                    base_url=api_base,
                    timeout=8,
                    delay=0.3,
                )
                api_rapor = api_scanner.scan(openapi_url=openapi_url)
                print(api_rapor.summary)

            elif secim == "12":
                print(
                    "\n[*] Web Arayüzü Başlatılıyor... "
                    "Tarayıcınızdan http://localhost:8000 "
                    "adresine gidin. Çıkmak için CTRL+C yapın."
                )
                try:
                    import uvicorn
                    uvicorn.run(
                        "web.app:app",
                        host="127.0.0.1",
                        port=8000,
                        reload=False,
                    )
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
            nmap_calistir(
                ["sudo", "nmap", hiz, "-O", hedef], hedef, "os_analizi"
            )
        elif secim == "5":
            nmap_calistir(
                ["sudo", "nmap", hiz, "-A", hedef], hedef, "agresif_tarama"
            )
        elif secim == "6":
            sonuc = zafiyet_tara(hedef)
            rapor_yaz(f"{hedef}_zafiyet", sonuc)
            print(sonuc)
        else:
            print("[-] Geçersiz seçim.")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "NetScanner: Gelişmiş Ağ Trafiği ve Güvenlik Analiz Platformu"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Örnekler:\n"
            "  sudo python3 main.py                       # İnteraktif menü\n"
            "  sudo python3 main.py --pcap trafik.pcap       # PCAP analizi\n"
            "  sudo python3 main.py --nmap-quick 192.168.1.1 # Hızlı Nmap\n"
            "  sudo python3 main.py --nmap-vuln 10.0.0.1    # Zafiyet tarama\n"
            "  sudo python3 main.py --live                   # Canlı izleme\n"
            "  python3 main.py --web                         # Web arayüzü\n"
        ),
    )

    # --- Paket Motoru Argümanları ---
    parser.add_argument(
        "-p", "--pcap",
        metavar="DOSYA",
        help="Analiz edilecek .pcap/.pcapng dosyasının yolu",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Canlı ağ trafiğini dinle ve anomali tespiti yap (root gerekir)",
    )

    # --- Nmap Entegrasyonu Argümanları ---
    nmap_group = parser.add_argument_group("Nmap Tarama Argümanları")
    nmap_group.add_argument(
        "--nmap-quick",
        metavar="HEDEF",
        help="Hızlı Nmap taraması (-F, Top 100 port)",
    )
    nmap_group.add_argument(
        "--nmap-service",
        metavar="HEDEF",
        help="Servis & versiyon tespiti (-sV)",
    )
    nmap_group.add_argument(
        "--nmap-full",
        metavar="HEDEF",
        help="Agresif tam tarama (-A) — root gerekir",
    )
    nmap_group.add_argument(
        "--nmap-vuln",
        metavar="HEDEF",
        help="NSE zafiyet taraması (--script=vuln)",
    )

    # --- Eski / Uyumluluk Argümanları ---
    parser.add_argument(
        "-t", "--target",
        metavar="HEDEF",
        help="(Eski) Hedef IP veya Domain adresi",
    )
    parser.add_argument(
        "--test-nmap",
        action="store_true",
        help="(Eski) Nmap entegrasyonunu test et; --target ile kullanılır",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Web arayüzünü (Dashboard) başlatır (http://localhost:8000)",
    )

    # --- Final Proje Yeni Modüller ---
    parser.add_argument(
        "--full-scan",
        metavar="HEDEF",
        help=(
            "Full Vulnerability Scanner: tüm modülleri zincirleyen "
            "otomatik tarama (Nmap + Trafik + API + Credential)"
        ),
    )
    parser.add_argument(
        "--credential-test",
        metavar="LOGIN_URL",
        help=(
            "Credential Tester: rate limiting, parola politikası "
            "ve account lockout tespiti"
        ),
    )
    parser.add_argument(
        "--api-scan",
        metavar="API_URL",
        help=(
            "API Security Scanner: OWASP API Top 10 ve BOLA tespiti "
            "(OpenAPI/Swagger spec desteği ile)"
        ),
    )
    parser.add_argument(
        "--openapi-url",
        metavar="SPEC_URL",
        help="OpenAPI/Swagger spec URL'si (--api-scan ile kullanılır)",
    )
    parser.add_argument(
        "--api-base-url",
        metavar="URL",
        help="Full scan için API base URL (opsiyonel)",
    )
    parser.add_argument(
        "--login-url",
        metavar="URL",
        help="Full scan için login URL (opsiyonel)",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------ #
    # Argüman Yönlendirme                                                  #
    # ------------------------------------------------------------------ #
    if len(sys.argv) == 1:
        # Argümansız çalıştırıldı → interaktif menü
        ana_menu()

    elif args.pcap:
        print(f"[*] {args.pcap} dosyası okunuyor ve analiz ediliyor...")
        reader = PcapReader(args.pcap)
        if reader.read_pcap():
            paketler = reader.parse_packets()
            analyzer = TrafficAnalyzer(paketler)
            sonuclar = analyzer.analyze()
            trafik_raporu_olustur("cli_pcap", sonuclar)
            markdown_guvenlik_raporu_olustur(
                hedef=args.pcap,
                trafik_sonuclar=sonuclar,
                connection_map=sonuclar.get("connection_map"),
            )

    elif args.live:
        print(
            "[*] Canlı Ağ İzleme Başlatılıyor..."
            " (Durdurmak için ENTER'a basın)"
        )
        sniffer = LiveSniffer()
        sniffer.start_sniffing()
        input()
        sniffer.stop_sniffing()
        paketler = sniffer.get_parsed_packets()
        analyzer = TrafficAnalyzer(paketler)
        sonuclar = analyzer.analyze()
        trafik_raporu_olustur("cli_live", sonuclar)
        markdown_guvenlik_raporu_olustur(
            hedef="Canli_Ag",
            trafik_sonuclar=sonuclar,
            connection_map=sonuclar.get("connection_map"),
        )

    elif args.nmap_quick:
        hedef = args.nmap_quick
        hiz = Ayarlar.TARAMA_HIZI
        print(f"[*] {hedef} için hızlı Nmap taraması başlatılıyor...")
        nmap_calistir(["nmap", hiz, "-F", hedef], hedef, "hizli_tarama")

    elif args.nmap_service:
        hedef = args.nmap_service
        hiz = Ayarlar.TARAMA_HIZI
        print(f"[*] {hedef} için servis/versiyon tespiti başlatılıyor...")
        nmap_calistir(["nmap", hiz, "-sV", hedef], hedef, "servis_analizi")

    elif args.nmap_full:
        hedef = args.nmap_full
        hiz = Ayarlar.TARAMA_HIZI
        print(f"[*] {hedef} için agresif tarama başlatılıyor...")
        nmap_calistir(
            ["sudo", "nmap", hiz, "-A", hedef], hedef, "agresif_tarama"
        )

    elif args.nmap_vuln:
        hedef = args.nmap_vuln
        print(f"[*] {hedef} için zafiyet taraması başlatılıyor...")
        sonuc = zafiyet_tara(hedef)
        rapor_yaz(f"{hedef}_zafiyet", sonuc)
        print(sonuc)

    elif args.test_nmap and args.target:
        print(f"[*] {args.target} için entegrasyon testi başlatılıyor...")
        hiz = Ayarlar.TARAMA_HIZI
        nmap_calistir(
            ["nmap", hiz, "-F", args.target], args.target, "test_tarama"
        )

    elif args.web:
        print(
            "[*] Web Arayüzü Başlatılıyor... "
            "Tarayıcınızdan http://localhost:8000 adresine gidin."
        )
        try:
            import uvicorn
            uvicorn.run(
                "web.app:app",
                host="127.0.0.1",
                port=8000,
                reload=False,
            )
        except ImportError:
            print("[-] HATA: Web arayüzü bileşenleri bulunamadı.")

    elif args.full_scan:
        hedef = args.full_scan
        print(f"[*] Full Vulnerability Scanner başlatılıyor → {hedef}")
        scanner = FullVulnerabilityScanner(
            target=hedef,
            pcap_file=args.pcap,
            api_base_url=getattr(args, "api_base_url", None),
            login_url=getattr(args, "login_url", None),
            openapi_url=getattr(args, "openapi_url", None),
        )
        scanner.run_full_scan()

    elif args.credential_test:
        login_url = args.credential_test
        print(f"[*] Credential Tester başlatılıyor → {login_url}")
        tester = CredentialTester(
            target_url=login_url,
            delay_between_requests=0.3,
        )
        rapor = tester.run_all_tests()
        print(rapor.summary)

    elif args.api_scan:
        api_url = args.api_scan
        openapi_url = getattr(args, "openapi_url", None)
        print(f"[*] API Security Scanner başlatılıyor → {api_url}")
        api_scanner = APISecurityScanner(
            base_url=api_url,
            timeout=8,
            delay=0.3,
        )
        api_rapor = api_scanner.scan(openapi_url=openapi_url)
        print(api_rapor.summary)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
