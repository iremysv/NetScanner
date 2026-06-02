# Sızma Testi Raporu — İrem Yasav

## Hedef Bilgisi

- **URL/IP:** `dummy.pcap`
- **Tarih:** 2026-06-02 21:24:16
- **Araçlar:** NetScanner (Nmap + Packet Engine)

---

## Bulgular

### 1. 🔴 [Kritik] SYN Flood / DDoS Saldırısı
> *Kaynak: Traffic Analyzer*

- **Açıklama:** 110 adet sadece SYN paketi (ACK beklenmeyen) gönderildi.
- **Risk:** Kaynak IP: 10.0.0.5. Sistem güvenliği tehdit altında olabilir.
- **Öneri:** SYN cookie korumasını etkinleştirin. Güvenlik duvarında rate-limiting uygulayın. DDoS koruma hizmeti (Cloudflare, AWS Shield) değerlendirin.

### 2. 🔴 [Kritik] Veri Sızdırma (Data Exfiltration)
> *Kaynak: Traffic Analyzer*

- **Açıklama:** Aşırı büyük payload aktarımı (60040 byte) Hedef: 1.2.3.4
- **Risk:** Kaynak IP: 10.0.0.5. Sistem güvenliği tehdit altında olabilir.
- **Öneri:** Büyük veri transferlerini DLP (Data Loss Prevention) sistemiyle izleyin. Anormal veri çıkışlarına karşı egress filtering uygulayın.

### 3. 🟠 [Yüksek] DNS Tünelleme Şüphesi
> *Kaynak: Traffic Analyzer*

- **Açıklama:** 60 adet anormal DNS isteği tespit edildi.
- **Risk:** Kaynak IP: 10.10.10.10. Sistem güvenliği tehdit altında olabilir.
- **Öneri:** DNS trafiğini bir güvenlik proxy'si üzerinden yönlendirin. Anormal uzunlukta DNS sorgularını filtreleyin. DNS over HTTPS (DoH) kullanımını değerlendirin.

---

## Özet

| Seviye | Bulgu Sayısı |
|--------|-------------|
| 🔴 Kritik | 2 |
| 🟠 Yüksek | 1 |
| 🟡 Orta   | 0 |
| 🟢 Düşük  | 0 |
| ⚪ Bilgi  | 0 |
| **Toplam** | **3** |

---

## 🗺️ Bağlantı Haritası

| Kaynak IP | Hedef IP | Portlar | Paket Sayısı |
|-----------|----------|---------|-------------|
| `10.0.0.5` | `192.168.1.1` | 80 | 111 |
| `10.0.0.5` | `1.2.3.4` | 443 | 111 |
| `10.10.10.10` | `1.1.1.1` | 53 | 60 |
| `192.168.1.100` | `8.8.8.8` | 53 | 10 |
| `172.16.0.5` | `192.168.1.200` | 80 | 1 |
| `104.21.43.12` | `192.168.1.100` | 54321 | 1 |

---
*Bu rapor NetScanner tarafından otomatik üretilmiştir. Bulgular manuel doğrulama gerektirebilir.*