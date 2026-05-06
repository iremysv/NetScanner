# -*- coding: utf-8 -*-
import subprocess
import re
from core import config as Ayarlar
from modules.nmap_integration.analyzer import analiz_et
from reports.reporter import rapor_yaz
from modules.nmap_integration.vulnerability import zafiyet_tara


def nmap_calistir(komut_listesi: list[str], hedef: str, rapor_adi: str) -> str:
    try:
        print(f"\n[+] İşlem başlatıldı: {' '.join(komut_listesi)}")
        sonuc = subprocess.run(
            komut_listesi, capture_output=True, text=True, check=True
        )

        # 1. Rapor oluşturucuya gönder (Tüm modlar için)
        rapor_yaz(hedef, sonuc.stdout)

        # 2. Portları yakalayıp Analiz Motoruna gönder
        # Örnek Regex Eşleşmesi: "80/tcp open" -> '80'
        acik_portlar = re.findall(r"(\d+)/tcp\s+open", sonuc.stdout)
        if acik_portlar:
            print(
                f"[*] {len(acik_portlar)} adet açık port tespit edildi, analiz motoruna iletiliyor...\n"
            )
            analiz_et(acik_portlar)

        print(f"[!] Tarama işlemi tamamlandı.")
        return sonuc.stdout
    except Exception as e:
        print(f"[-] Hata oluştu: {e}")


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

        # Ayarlar.py içindeki dinamik hız parametresi
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


if __name__ == "__main__":
    ana_menu()
