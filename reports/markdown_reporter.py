# -*- coding: utf-8 -*-
"""
reports/markdown_reporter.py

Nmap tarama sonuçları ve trafik analizi bulgularını birleştirerek
hoca tarafından beklenen formatta Markdown güvenlik raporu üretir.

Rapor formatı:
  # Sızma Testi Raporu — İrem Yasav
  ## Hedef Bilgisi
  ## Bulgular (Kritik / Yüksek / Orta / Düşük)
    - Açıklama / Risk / Öneri
  ## Özet Tablosu
"""
import os
import re
from datetime import datetime
from core import config as Ayarlar


# Severity öncelik sıralaması (sıralama için)
_SEVERITY_ORDER = {"Kritik": 0, "Yüksek": 1, "Orta": 2, "Düşük": 3}

# Anomali tipi → okunabilir başlık
_ANOMALY_LABELS: dict[str, str] = {
    "SYN_FLOOD_DDOS":          "SYN Flood / DDoS Saldırısı",
    "DATA_EXFILTRATION":       "Veri Sızdırma (Data Exfiltration)",
    "HTTP_MALICIOUS_PAYLOAD":  "Zararlı HTTP Payload Tespiti",
    "PORT_SCAN":               "Port Tarama Girişimi",
    "DNS_TUNNELING_SUSPICION": "DNS Tünelleme Şüphesi",
    "DNS_DPI_ANOMALY":         "Anormal DNS Sorgusu (DPI)",
}

# Anomali tipi → Öneri metinleri
_ANOMALY_RECOMMENDATIONS: dict[str, str] = {
    "SYN_FLOOD_DDOS": (
        "SYN cookie korumasını etkinleştirin. "
        "Güvenlik duvarında rate-limiting uygulayın. "
        "DDoS koruma hizmeti (Cloudflare, AWS Shield) değerlendirin."
    ),
    "DATA_EXFILTRATION": (
        "Büyük veri transferlerini DLP (Data Loss Prevention) "
        "sistemiyle izleyin. "
        "Anormal veri çıkışlarına karşı egress filtering uygulayın."
    ),
    "HTTP_MALICIOUS_PAYLOAD": (
        "WAF (Web Application Firewall) kurun. "
        "Tüm kullanıcı girdilerini sunucu tarafında doğrulayın. "
        "SQL Injection ve XSS karşıtı güvenli kodlama pratiklerini uygulayın."
    ),
    "PORT_SCAN": (
        "Güvenlik duvarında port tarama tespiti etkinleştirin. "
        "Saldırı kaynağı IP'yi geçici olarak engelleyin (fail2ban). "
        "Gereksiz açık portları kapatın."
    ),
    "DNS_TUNNELING_SUSPICION": (
        "DNS trafiğini bir güvenlik proxy'si üzerinden yönlendirin. "
        "Anormal uzunlukta DNS sorgularını filtreleyin. "
        "DNS over HTTPS (DoH) kullanımını değerlendirin."
    ),
    "DNS_DPI_ANOMALY": (
        "Uzun ve şifreli görünen DNS sorgularını inceleyin. "
        "DNS güvenlik duvarı kuralları ekleyin."
    ),
}


def _severity_emoji(severity: str) -> str:
    mapping = {
        "Kritik": "🔴",
        "Yüksek": "🟠",
        "Orta":   "🟡",
        "Düşük":  "🟢",
    }
    return mapping.get(severity, "⚪")


def markdown_guvenlik_raporu_olustur(
    hedef: str,
    trafik_sonuclar: dict | None = None,
    acik_portlar: list[str] | None = None,
    nmap_ciktisi: str | None = None,
) -> str:
    """
    Nmap ve trafik analizi bulgularını birleştirerek Markdown rapor üretir.

    Args:
        hedef: Hedef IP/domain
        trafik_sonuclar: TrafficAnalyzer.analyze() çıktısı
        acik_portlar: Nmap'ten elde edilen açık port listesi (str)
        nmap_ciktisi: Ham nmap stdout (port çıkarımı için)

    Returns:
        Oluşturulan rapor dosyasının mutlak yolu
    """
    tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dosya_tarih = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    bulgular: list[dict] = []

    # ---------------------------------------------------------------
    # 1. Nmap Bulguları — Açık Portlar
    # ---------------------------------------------------------------
    portlar: list[str] = list(acik_portlar or [])
    if nmap_ciktisi and not portlar:
        portlar = re.findall(r"(\d+)/tcp\s+open", nmap_ciktisi)

    for port in portlar:
        info = Ayarlar.PORT_SECURITY_INFO.get(str(port))
        if info:
            bulgular.append({
                "baslik": (
                    f"Açık Port — {info['servis']} ({port}/tcp)"
                ),
                "kaynak":   "Nmap",
                "severity": info["severity"],
                "aciklama": info["aciklama"],
                "risk":     info["risk"],
                "oneri":    info["oneri"],
            })
        else:
            bulgular.append({
                "baslik":   f"Açık Port — {port}/tcp",
                "kaynak":   "Nmap",
                "severity": "Bilgi",
                "aciklama": f"Port {port}/tcp açık durumda.",
                "risk": (
                    "Bilinmeyen servis güvenlik açığı oluşturabilir."
                ),
                "oneri": (
                    "Port kullanım amacını doğrulayın. "
                    "Gerekli değilse kapatın."
                ),
            })

    # ---------------------------------------------------------------
    # 2. Trafik Analizi Bulguları — Anomaliler
    # ---------------------------------------------------------------
    if trafik_sonuclar:
        anomalies = trafik_sonuclar.get("anomalies", [])
        for anomaly in anomalies:
            atype = anomaly.get("type", "UNKNOWN")
            severity = Ayarlar.ANOMALY_SEVERITY.get(atype, "Orta")
            label = _ANOMALY_LABELS.get(atype, atype)
            oneri = _ANOMALY_RECOMMENDATIONS.get(
                atype,
                "İlgili güvenlik ekibiyle iletişime geçin."
            )
            bulgular.append({
                "baslik":   label,
                "kaynak":   "Traffic Analyzer",
                "severity": severity,
                "aciklama": anomaly.get("details", ""),
                "risk": (
                    f"Kaynak IP: {anomaly.get('source_ip', 'Bilinmiyor')}. "
                    "Sistem güvenliği tehdit altında olabilir."
                ),
                "oneri":    oneri,
            })

    # Bulgular Severity'ye göre sırala
    bulgular.sort(
        key=lambda x: _SEVERITY_ORDER.get(x["severity"], 99)
    )

    # ---------------------------------------------------------------
    # 3. Markdown İçeriği Oluştur
    # ---------------------------------------------------------------
    lines: list[str] = []
    lines.append("# Sızma Testi Raporu — İrem Yasav\n")
    lines.append("## Hedef Bilgisi\n")
    lines.append(f"- **URL/IP:** `{hedef}`")
    lines.append(f"- **Tarih:** {tarih}")
    lines.append(f"- **Araçlar:** NetScanner (Nmap + Packet Engine)")
    lines.append("")

    # Özet sayaç
    sayac: dict[str, int] = {
        "Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Bilgi": 0
    }
    for b in bulgular:
        sev = b["severity"]
        sayac[sev] = sayac.get(sev, 0) + 1

    lines.append("---\n")
    lines.append("## Bulgular\n")

    if not bulgular:
        lines.append(
            "> ✅ Analiz tamamlandı. "
            "Kritik bir güvenlik bulgusu tespit edilmedi.\n"
        )
    else:
        for i, b in enumerate(bulgular, 1):
            sev = b["severity"]
            emoji = _severity_emoji(sev)
            lines.append(
                f"### {i}. {emoji} [{sev}] {b['baslik']}"
            )
            lines.append(f"> *Kaynak: {b['kaynak']}*\n")
            lines.append(f"- **Açıklama:** {b['aciklama']}")
            lines.append(f"- **Risk:** {b['risk']}")
            lines.append(f"- **Öneri:** {b['oneri']}")
            lines.append("")

    lines.append("---\n")
    lines.append("## Özet\n")
    lines.append("| Seviye | Bulgu Sayısı |")
    lines.append("|--------|-------------|")
    lines.append(f"| 🔴 Kritik | {sayac['Kritik']} |")
    lines.append(f"| 🟠 Yüksek | {sayac['Yüksek']} |")
    lines.append(f"| 🟡 Orta   | {sayac['Orta']} |")
    lines.append(f"| 🟢 Düşük  | {sayac['Düşük']} |")
    lines.append(f"| ⚪ Bilgi  | {sayac['Bilgi']} |")
    lines.append(f"| **Toplam** | **{len(bulgular)}** |")
    lines.append("")
    lines.append("---")
    lines.append(
        "*Bu rapor NetScanner tarafından otomatik üretilmiştir. "
        "Bulgular manuel doğrulama gerektirebilir.*"
    )

    icerik = "\n".join(lines)

    # ---------------------------------------------------------------
    # 4. Dosyaya Yaz
    # ---------------------------------------------------------------
    dizin = getattr(
        Ayarlar, "MARKDOWN_RAPOR_DIZINI", "taramalar/security_reports"
    )
    if not os.path.exists(dizin):
        os.makedirs(dizin)

    hedef_safe = re.sub(r"[^\w\-.]", "_", hedef)
    dosya_adi = os.path.join(
        dizin, f"security_report_{hedef_safe}_{dosya_tarih}.md"
    )
    with open(dosya_adi, "w", encoding="utf-8") as f:
        f.write(icerik)

    print(
        f"\n[+] Markdown Güvenlik Raporu oluşturuldu:\n"
        f"    {dosya_adi}"
    )
    return dosya_adi
