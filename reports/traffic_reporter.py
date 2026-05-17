# -*- coding: utf-8 -*-
import os
import json
from datetime import datetime
from core import config as Ayarlar


def trafik_raporu_olustur(rapor_adi_onek: str, sonuclar: dict) -> None:
    tarih = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dizin = getattr(
        Ayarlar, "TRAFIK_RAPOR_DIZINI", "taramalar/traffic_reports"
    )

    if not os.path.exists(dizin):
        os.makedirs(dizin)

    dosya_adi_txt = os.path.join(
        dizin, f"traffic_rapor_{rapor_adi_onek}_{tarih}.txt"
    )
    dosya_adi_json = os.path.join(
        dizin, f"traffic_rapor_{rapor_adi_onek}_{tarih}.json"
    )
    dosya_adi_html = os.path.join(
        dizin, f"traffic_rapor_{rapor_adi_onek}_{tarih}.html"
    )

    # 1. JSON Formatında Kaydetme
    with open(dosya_adi_json, "w", encoding="utf-8") as f:
        json.dump(sonuclar, f, indent=4, ensure_ascii=False)

    # 2. İnsan Tarafından Okunabilir TXT Formatında Kaydetme
    with open(dosya_adi_txt, "w", encoding="utf-8") as f:
        f.write("--- NETSCANNER TRAFİK ANALİZ RAPORU ---\n")
        f.write(f"Tarih: {tarih}\n")
        f.write(
            f"Toplam İncelenen Paket: "
            f"{sonuclar.get('total_packets', 0)}\n"
        )
        f.write("-" * 40 + "\n\n")

        f.write("[PROTOKOL DAĞILIMI]\n")
        protokoller = sonuclar.get("protocol_distribution", {})
        for proto, sayi in protokoller.items():
            f.write(f"  - {proto}: {sayi} paket\n")
        f.write("\n")

        f.write("[EN ÇOK TRAFİK ÜRETEN IP'LER (TOP TALKERS & OSINT)]\n")
        top_talkers = sonuclar.get("top_talkers", [])
        for talker in top_talkers:
            f.write(
                f"  - {talker['ip']}: {talker['count']} paket "
                f"[Konum: {talker['location']}]\n"
            )
        f.write("\n")

        f.write("[TESPİT EDİLEN ANOMALİLER]\n")
        anomaliler = sonuclar.get("anomalies", [])
        if not anomaliler:
            f.write("  - Herhangi bir anomali tespit edilmedi.\n")
        else:
            for anomali in anomaliler:
                f.write(
                    f"  ! DİKKAT [{anomali.get('type')}]: "
                    f"IP: {anomali.get('source_ip')} "
                    f"-> {anomali.get('details')}\n"
                )
        f.write("\n" + "-" * 40 + "\n")

    # 3. Profesyonel HTML Formatında Kaydetme
    html_content = _generate_html(tarih, sonuclar)
    with open(dosya_adi_html, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(
        f"\n[+] Trafik analiz raporu oluşturuldu:"
        f"\n    TXT:  {dosya_adi_txt}"
        f"\n    JSON: {dosya_adi_json}"
        f"\n    HTML: {dosya_adi_html}"
    )


def _generate_html(tarih: str, sonuclar: dict) -> str:
    """HTML rapor içeriğini dinamik olarak oluşturur."""

    # CSS Stilleri
    css = """
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f4f7f6; color: #333; margin: 0; padding: 20px;
    }
    h1, h2 {
        color: #2c3e50;
        border-bottom: 2px solid #3498db;
        padding-bottom: 5px;
    }
    .container {
        max-width: 900px; margin: auto; background: #fff;
        padding: 20px; border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    .summary-box {
        background: #e8f4f8; padding: 15px;
        border-left: 5px solid #3498db; margin-bottom: 20px;
    }
    table {
        width: 100%; border-collapse: collapse;
        margin-top: 10px; margin-bottom: 20px;
    }
    th, td {
        padding: 12px; text-align: left;
        border-bottom: 1px solid #ddd;
    }
    th { background-color: #3498db; color: white; }
    tr:hover { background-color: #f1f1f1; }
    .alert {
        background: #ffeded; border-left: 5px solid #e74c3c;
        padding: 15px; margin-bottom: 10px;
    }
    .alert-title { color: #c0392b; font-weight: bold; }
    .badge {
        display: inline-block; padding: 5px 10px; border-radius: 15px;
        font-size: 12px; font-weight: bold; color: white; background: #34495e;
    }
    """

    # Top Talkers Tablosu
    top_talkers = sonuclar.get("top_talkers", [])
    talkers_html = (
        "<table><tr>"
        "<th>Sıra</th><th>IP Adresi</th>"
        "<th>Paket Sayısı</th><th>Coğrafi Konum (OSINT)</th>"
        "</tr>"
    )
    for i, t in enumerate(top_talkers):
        talkers_html += (
            f"<tr><td>{i+1}</td><td>{t['ip']}</td>"
            f"<td>{t['count']}</td><td>{t['location']}</td></tr>"
        )
    talkers_html += "</table>"

    # Protokol Dağılımı Tablosu
    protocol_dist = sonuclar.get("protocol_distribution", {})
    proto_html = "<table><tr><th>Protokol</th><th>Paket Sayısı</th></tr>"
    for p, c in protocol_dist.items():
        proto_html += (
            f"<tr><td><span class='badge'>{p}</span></td>"
            f"<td>{c}</td></tr>"
        )
    proto_html += "</table>"

    # Anomaliler Listesi
    anomalies = sonuclar.get("anomalies", [])
    anomalies_html = ""
    if not anomalies:
        anomalies_html = (
            "<p style='color: green; font-weight: bold;'>"
            "Ağda herhangi bir anomali tespit edilmedi.</p>"
        )
    else:
        for a in anomalies:
            anomalies_html += (
                f"<div class='alert'>"
                f"<span class='alert-title'>[{a.get('type')}]</span> "
                f"Şüpheli IP: <strong>{a.get('source_ip')}</strong>"
                f"<br>Detay: {a.get('details')}</div>"
            )

    html_template = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>NetScanner Trafik Analiz Raporu</title>
        <style>{css}</style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ NetScanner Gelişmiş Ağ Analiz Raporu</h1>
            <div class="summary-box">
                <strong>Oluşturulma Tarihi:</strong> {tarih} <br>
                <strong>İncelenen Toplam Paket:</strong>
                {sonuclar.get('total_packets', 0)}
            </div>

            <h2>🚨 Tespit Edilen Anomaliler ve Tehditler</h2>
            {anomalies_html}

            <h2>🌍 En Aktif IP Adresleri (Top Talkers)</h2>
            {talkers_html}

            <h2>📊 Protokol Dağılımı</h2>
            {proto_html}
            <p style="text-align: center; color: #7f8c8d;
                font-size: 12px; margin-top: 40px;">
                Bu rapor NetScanner Packet Engine tarafından
                otomatik üretilmiştir.
            </p>
        </div>
    </body>
    </html>
    """
    return html_template
