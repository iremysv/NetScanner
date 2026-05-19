# -*- coding: utf-8 -*-

# Nmap Tarama Hızı (T3: Normal, T4: Hızlı, T5: Agresif)
TARAMA_HIZI = "-T4"

# Varsayılan Rapor Klasörü
RAPOR_DIZINI = "taramalar"

# Versiyon ve OS Tespiti bayrakları
DETAYLI_MOD = "-sV -O"

# Trafik Analizi ve Anomali Eşik Değerleri
# Bir IP'nin kısa sürede taradığı farklı port sayısı sınırı
PORT_SCAN_THRESHOLD = 15
# Kısa sürede aşırı DNS isteği yapma sınırı
DNS_TUNNELING_THRESHOLD = 50
# Bir IP'nin cevap almadan gönderdiği SYN paket sayısı
SYN_FLOOD_THRESHOLD = 100
# Aynı IP için farklı MAC adreslerinden gelen ARP sayısı
ARP_SPOOF_THRESHOLD = 5
# Bayt cinsinden tek seferde giden aşırı büyük veri boyutu (Data Exfiltration)
LARGE_PAYLOAD_THRESHOLD = 50000
TRAFIK_RAPOR_DIZINI = "taramalar/traffic_reports"

# Markdown Güvenlik Rapor Dizini
MARKDOWN_RAPOR_DIZINI = "taramalar/security_reports"

# Anomali Türü → Severity Seviyesi Eşlemesi
# Kritik / Yüksek / Orta / Düşük / Bilgi
ANOMALY_SEVERITY: dict[str, str] = {
    "SYN_FLOOD_DDOS":          "Kritik",
    "DATA_EXFILTRATION":       "Kritik",
    "HTTP_MALICIOUS_PAYLOAD":  "Kritik",
    "PORT_SCAN":               "Yüksek",
    "DNS_TUNNELING_SUSPICION": "Yüksek",
    "DNS_DPI_ANOMALY":         "Orta",
}

# Nmap Port → Güvenlik Bilgisi (Açıklama / Risk / Öneri)
PORT_SECURITY_INFO: dict[str, dict[str, str]] = {
    "21": {
        "servis": "FTP",
        "severity": "Kritik",
        "aciklama": (
            "FTP servisi internete açık durumda. "
            "Kimlik bilgileri şifresiz (clear-text) iletilir."
        ),
        "risk": (
            "Kimlik bilgisi ele geçirme (Credential Theft), "
            "Adam-in-the-Middle (MITM) saldırısı."
        ),
        "oneri": (
            "FTP servisini kapatın. "
            "Güvenli alternatif olarak SFTP veya SCP kullanın."
        ),
    },
    "22": {
        "servis": "SSH",
        "severity": "Orta",
        "aciklama": "SSH servisi erişime açık.",
        "risk": "Yetkisiz uzak erişim, brute-force parola saldırıları.",
        "oneri": (
            "Parola tabanlı girişi devre dışı bırakın, "
            "SSH key authentication kullanın. "
            "Fail2ban ile brute-force koruması ekleyin."
        ),
    },
    "23": {
        "servis": "Telnet",
        "severity": "Kritik",
        "aciklama": (
            "Telnet servisi açık. Tüm veriler şifresiz iletilir."
        ),
        "risk": "Kimlik bilgisi ele geçirme, MITM, oturum kaçırma.",
        "oneri": "Telnet'i devre dışı bırakın; SSH kullanın.",
    },
    "80": {
        "servis": "HTTP",
        "severity": "Orta",
        "aciklama": "HTTP web servisi şifresiz olarak çalışıyor.",
        "risk": (
            "XSS, SQL Injection, MITM, "
            "açık dizin listeleme saldırıları."
        ),
        "oneri": (
            "HTTPS'e geçiş yapın. "
            "HSTS başlığını etkinleştirin."
        ),
    },
    "443": {
        "servis": "HTTPS",
        "severity": "Düşük",
        "aciklama": "HTTPS servisi çalışıyor.",
        "risk": (
            "SSL/TLS yapılandırma zafiyetleri, "
            "süresi dolmuş sertifika."
        ),
        "oneri": (
            "SSL/TLS sürümünü kontrol edin (TLS 1.2+ önerilir). "
            "Sertifika geçerliliğini doğrulayın."
        ),
    },
    "445": {
        "servis": "SMB",
        "severity": "Kritik",
        "aciklama": (
            "SMB (Windows dosya paylaşımı) servisi internete açık."
        ),
        "risk": (
            "EternalBlue, WannaCry gibi kritik exploitler. "
            "Yetkisiz ağ paylaşım erişimi."
        ),
        "oneri": (
            "SMB portunu (445) internete kapatın. "
            "Windows güvenlik yamalarını uygulayın."
        ),
    },
    "3306": {
        "servis": "MySQL",
        "severity": "Kritik",
        "aciklama": "MySQL veritabanı servisi dışarıya açık.",
        "risk": (
            "Doğrudan veritabanı erişimi, "
            "SQL injection, veri sızıntısı."
        ),
        "oneri": (
            "Veritabanı portunu güvenlik duvarı ile kapatın. "
            "Yalnızca uygulama sunucusundan erişime izin verin."
        ),
    },
    "3389": {
        "servis": "RDP",
        "severity": "Yüksek",
        "aciklama": "RDP (Uzak Masaüstü) servisi internete açık.",
        "risk": (
            "Brute-force, BlueKeep zafiyeti, "
            "yetkisiz uzak masaüstü erişimi."
        ),
        "oneri": (
            "RDP'yi VPN arkasına alın. "
            "NLA (Network Level Authentication) aktif edin. "
            "Güçlü parola politikası uygulayın."
        ),
    },
    "8080": {
        "servis": "HTTP-Proxy",
        "severity": "Orta",
        "aciklama": "Alternatif HTTP portu (proxy/web) açık.",
        "risk": "Açık proxy, web servis zafiyetleri.",
        "oneri": (
            "Gerekli değilse portu kapatın. "
            "Erişimi IP tabanlı whitelist ile kısıtlayın."
        ),
    },
}
