# -*- coding: utf-8 -*-
import subprocess
import re
from modules.nmap_integration.analyzer import analiz_et
from reports.reporter import rapor_yaz


def nmap_calistir(komut_listesi: list[str], hedef: str, rapor_adi: str) -> str | None:
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

        print("[!] Tarama işlemi tamamlandı.")
        return sonuc.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Nmap komutu başarısız oldu: {e.stderr}")
        return None
    except Exception as e:
        print(f"[-] Beklenmeyen hata oluştu: {e}")
        return None
