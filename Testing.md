# NetScanner — Test Rehberi

## Genel Bakış

NetScanner, **pytest** test çerçevesi ve **pytest-cov** kapsam raporlama aracı ile kapsamlı biçimde test edilmiştir.

| Metrik | Değer |
|---|---|
| **Toplam Test Sayısı** | 95 |
| **Başarılı Testler** | 95/95 |
| **Kod Kapsamı (Coverage)** | %73 |
| **Test Çerçevesi** | pytest 9+ |

---

## Hızlı Başlangıç

### Tüm testleri çalıştır
```bash
pytest Tests/
```

### Ayrıntılı çıktıyla çalıştır
```bash
pytest Tests/ -v
```

### Coverage raporu ile çalıştır
```bash
pytest Tests/ --cov=modules --cov=core --cov=reports --cov-report=term-missing
```

### HTML coverage raporu üret (htmlcov/ klasörüne)
```bash
pytest Tests/ --cov=modules --cov=core --cov=reports --cov-report=html
```

---

## Test Yapısı

```
Tests/
├── test_config.py          # core.config eşik değerleri (11 test)
├── test_pcap_reader.py     # PcapReader okuma ve parse (14 test)
├── test_traffic_analyzer.py# TrafficAnalyzer anomali tespiti (13 test)
├── test_reporter.py        # Rapor oluşturma (JSON/TXT/HTML) (28 test)
└── test_nmap_modules.py    # Nmap entegrasyon modülleri (29 test)
```

### Test Kategorileri

#### `test_config.py` — Yapılandırma Değerleri
- Tüm eşik değerlerinin (`PORT_SCAN_THRESHOLD`, `SYN_FLOOD_THRESHOLD`, vb.) tanımlı ve pozitif tam sayı olduğunu doğrular
- Eşik değerleri hiyerarşisini (`PORT_SCAN < SYN_FLOOD`) kontrol eder
- Rapor dizini tanımlarının geçerliliğini doğrular

#### `test_pcap_reader.py` — PCAP Dosya Okuyucu
- Var olmayan dosya ile güvenli başarısızlık
- `dummy.pcap` ile gerçek okuma ve parse testi
- Paket veri yapısı alanlarının varlığını doğrulama (`src_ip`, `dst_ip`, `protocol`, vb.)

#### `test_traffic_analyzer.py` — Trafik Analizi ve Anomali Tespiti
- Boş paket listesiyle güvenli çalışma
- Protocol dağılımı ve top talkers hesaplama
- **Anomali tespiti:** Port Tarama, DNS Tunneling, SYN Flood, Veri Sızdırma, HTTP Zararlı Payload

#### `test_reporter.py` — Rapor Modülleri
- `rapor_yaz()`: Dosya oluşturma, başlık/içerik doğrulama, dizin oluşturma
- `trafik_raporu_olustur()`: JSON/TXT/HTML üçlü format çıkışı
- `_generate_html()`: HTML yapı doğrulaması, anomali alert kutuları
- `monkeypatch` ile gerçek dosya yazma işlemleri izole edilmiştir

#### `test_nmap_modules.py` — Nmap Entegrasyon Modülleri
- `analiz_et()`: 6 bilinen port için doğru çıktı, bilinmeyen port işleme
- `zafiyet_tara()`: subprocess mocklama, hata toleransı, NSE script kontrolü
- `nmap_calistir()`: başarılı/başarısız tarama dönüş değerleri, rapor oluşturma, port analiz tetiklemesi

---

## Gereksinimler

```bash
# Test bağımlılıklarını kur
pip install pytest pytest-cov
# veya
pip install -e ".[dev]"
```

---

## CI/CD Entegrasyonu

Proje `.github/` dizininde CI workflow'u desteklemektedir. Coverage eşiği **%70** olarak yapılandırılmıştır (`Pyproject.toml → [tool.coverage.report]`).

```toml
[tool.coverage.report]
fail_under = 70
```
