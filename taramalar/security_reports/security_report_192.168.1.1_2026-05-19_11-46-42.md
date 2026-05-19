# Sızma Testi Raporu — İrem Yasav

## Hedef Bilgisi

- **URL/IP:** `192.168.1.1`
- **Tarih:** 2026-05-19 11:46:42
- **Araçlar:** NetScanner (Nmap + Packet Engine)

---

## Bulgular

### 1. 🟠 [Yüksek] Port Tarama Girişimi
> *Kaynak: Traffic Analyzer*

- **Açıklama:** Çok fazla port
- **Risk:** Kaynak IP: 10.0.0.5. Sistem güvenliği tehdit altında olabilir.
- **Öneri:** Güvenlik duvarında port tarama tespiti etkinleştirin. Saldırı kaynağı IP'yi geçici olarak engelleyin (fail2ban). Gereksiz açık portları kapatın.

### 2. 🟡 [Orta] Açık Port — HTTP (80/tcp)
> *Kaynak: Nmap*

- **Açıklama:** HTTP web servisi şifresiz olarak çalışıyor.
- **Risk:** XSS, SQL Injection, MITM, açık dizin listeleme saldırıları.
- **Öneri:** HTTPS'e geçiş yapın. HSTS başlığını etkinleştirin.

### 3. 🟡 [Orta] Açık Port — SSH (22/tcp)
> *Kaynak: Nmap*

- **Açıklama:** SSH servisi erişime açık.
- **Risk:** Yetkisiz uzak erişim, brute-force parola saldırıları.
- **Öneri:** Parola tabanlı girişi devre dışı bırakın, SSH key authentication kullanın. Fail2ban ile brute-force koruması ekleyin.

---

## Özet

| Seviye | Bulgu Sayısı |
|--------|-------------|
| 🔴 Kritik | 0 |
| 🟠 Yüksek | 1 |
| 🟡 Orta   | 2 |
| 🟢 Düşük  | 0 |
| ⚪ Bilgi  | 0 |
| **Toplam** | **3** |

---
*Bu rapor NetScanner tarafından otomatik üretilmiştir. Bulgular manuel doğrulama gerektirebilir.*