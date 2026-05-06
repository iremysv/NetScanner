# -*- coding: utf-8 -*-


def analiz_et(port_listesi: list[str]) -> None:
    # Teknik analiz rehberi
    rehber = {
        "80": "🌐 HTTP: Web zafiyetleri (XSS, SQL Injection) ve açık dizin taraması yapılması önerilir.",
        "443": "🔐 HTTPS: SSL/TLS yapılandırması ve güvenli veri iletimi kontrol edilmelidir.",
        "21": "📁 FTP: Kimlik doğrulama mekanizmaları ve kaba kuvvet (Brute Force) riskleri incelenmelidir.",
        "22": "🔑 SSH: Uzaktan erişim güvenliği ve yetkisiz giriş denemeleri analiz edilmelidir.",
        "445": "🖥️ SMB: Ağ paylaşım izinleri ve servis zafiyetleri kontrol edilmelidir.",
        "3389": "🚪 RDP: Uzak masaüstü protokolü güvenliği ve yetki yükseltme riskleri değerlendirilmelidir.",
    }

    print("\n" + "=" * 60)
    print("🛡️  SİSTEM GÜVENLİK ANALİZİ VE TEKNİK ÖNERİLER  🛡️")
    print("=" * 60)

    tespit_edildi = False
    for port in port_listesi:
        p_str = str(port)
        if p_str in rehber:
            print(f"[!] {rehber[p_str]}")
            tespit_edildi = True

    if not tespit_edildi:
        print("[+] Mevcut portlar için kritik bir yapılandırma önerisi bulunamadı.")

    print("=" * 60 + "\n")
