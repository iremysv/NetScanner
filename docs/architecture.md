# NetScanner — Sistem Mimarisi

## Genel Bakış

NetScanner; modüler, katmanlı bir mimari üzerine inşa edilmiş bir **Ağ Güvenlik Analiz Platformu**'dur. Uygulama iki farklı arayüz sunar: **CLI (Komut Satırı)** ve **Web Dashboard (FastAPI)**.

---

## Katmanlı Mimari Diyagramı

```
┌─────────────────────────────────────────────────────┐
│                   SUNUM KATMANI                      │
│  ┌──────────────────┐    ┌────────────────────────┐ │
│  │    CLI (main.py) │    │  Web Dashboard         │ │
│  │  İnteraktif Menü │    │  (FastAPI + WebSocket) │ │
│  └────────┬─────────┘    └──────────┬─────────────┘ │
└───────────┼──────────────────────────┼───────────────┘
            │                          │
┌───────────┼──────────────────────────┼───────────────┐
│           │    UYGULAMA KATMANI      │               │
│  ┌────────▼──────────────────────────▼─────────────┐ │
│  │               MODÜLLER                          │ │
│  │                                                 │ │
│  │  ┌───────────────────┐  ┌──────────────────┐   │ │
│  │  │  PACKET ENGINE    │  │ NMAP INTEGRATION │   │ │
│  │  │                   │  │                  │   │ │
│  │  │ • pcap_reader.py  │  │ • scanner.py     │   │ │
│  │  │ • live_sniffer.py │  │ • analyzer.py    │   │ │
│  │  │ • traffic_        │  │ • vulnerability  │   │ │
│  │  │   analyzer.py     │  │   .py            │   │ │
│  │  └────────┬──────────┘  └────────┬─────────┘   │ │
│  └───────────┼────────────────────── ┼─────────────┘ │
└──────────────┼────────────────────── ┼───────────────┘
               │                       │
┌──────────────┼────────────────────── ┼───────────────┐
│              │    ÇEKIRDEK KATMANI   │               │
│  ┌───────────▼───────────────────────▼─────────────┐ │
│  │  core/config.py  — Merkezi yapılandırma          │ │
│  └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────-─┘
               │                       │
┌──────────────┼────────────────────── ┼───────────────┐
│              │   RAPORLAMA KATMANI   │               │
│  ┌───────────▼───────────────────────▼─────────────┐ │
│  │  reports/reporter.py       — Nmap TXT raporları  │ │
│  │  reports/traffic_reporter.py — JSON/TXT/HTML      │ │
│  └──────────────────────────────────────────────────┘ │
│                 taramalar/  ←  Çıktı Dizini           │
└───────────────────────────────────────────────────────┘
```

---

## Modül Açıklamaları

### `core/`
| Dosya | Görev |
|---|---|
| `config.py` | Tüm uygulama genelinde kullanılan eşik değerleri ve dizin sabitleri |

### `modules/packet_engine/`
| Dosya | Görev |
|---|---|
| `pcap_reader.py` | `.pcap`/`.pcapng` dosyalarını scapy ile okur ve dict listesine parse eder |
| `live_sniffer.py` | Ağ arayüzünden gerçek zamanlı paket yakalar (arka plan thread) |
| `traffic_analyzer.py` | Paket listesini analiz eder; protokol dağılımı, top talkers ve anomali tespiti yapar |

### `modules/nmap_integration/`
| Dosya | Görev |
|---|---|
| `scanner.py` | Nmap komutunu çalıştırır, stdout'u rapor eder ve açık portları analiz motoruna iletir |
| `analyzer.py` | Açık port listesine göre güvenlik önerileri sunar |
| `vulnerability.py` | NSE `--script=vuln` ile kapsamlı zafiyet taraması yapar |

### `reports/`
| Dosya | Görev |
|---|---|
| `reporter.py` | Nmap tarama sonuçlarını TXT formatında `taramalar/` dizinine yazar |
| `traffic_reporter.py` | Trafik analizi sonuçlarını JSON, TXT ve HTML formatında kaydeder |

### `web/`
| Dosya | Görev |
|---|---|
| `app.py` | FastAPI uygulaması; REST API (`/api/scan`, `/api/pcap_upload`, `/api/sniff/*`) ve WebSocket (`/ws/traffic`) endpoint'leri |
| `templates/index.html` | Glassmorphism tasarımlı web dashboard UI |
| `static/style.css` | Dashboard CSS (dark theme) |
| `static/script.js` | Dashboard JavaScript (WebSocket, API çağrıları, dinamik render) |

---

## Veri Akışı

### PCAP Analizi Akışı
```
.pcap dosyası
     │
     ▼
PcapReader.read_pcap()
     │ scapy rdpcap()
     ▼
PcapReader.parse_packets()
     │ [{"src_ip", "dst_ip", "protocol", "length", ...}]
     ▼
TrafficAnalyzer.analyze()
     │ {total_packets, protocol_distribution, top_talkers, anomalies}
     ▼
trafik_raporu_olustur()
     │
     ├── traffic_rapor_*.json
     ├── traffic_rapor_*.txt
     └── traffic_rapor_*.html
```

### Canlı Sniffer Akışı
```
Ağ Arayüzü (eth0 / en0)
     │
     ▼
LiveSniffer.start_sniffing()  ← arka plan thread
     │ scapy sniff() + callback
     ▼
LiveSniffer._parsed_packets (thread-safe list)
     │ periyodik WebSocket yayını
     ▼
Web Dashboard (gerçek zamanlı)
     │
     ▼  (sniff durdurulunca)
TrafficAnalyzer.analyze()
     │
     ▼
trafik_raporu_olustur()
```

### Nmap Tarama Akışı
```
Hedef IP / Domain
     │
     ▼
nmap_calistir(komut, hedef, rapor_adi)
     │ subprocess.run()
     ├── stdout → rapor_yaz() → taramalar/*.txt
     │
     └── açık portlar → analiz_et() → konsol çıktısı
```

---

## Tasarım Prensipleri

- **Katmanlı Mimari:** Sunum, uygulama, çekirdek ve raporlama katmanları birbirinden bağımsızdır
- **Tek Sorumluluk:** Her modül tek bir görevi yerine getirir
- **Savunmacı Programlama:** Tüm harici çağrılar (subprocess, scapy, disk I/O) try/except ile sarılmıştır
- **Test Edilebilirlik:** Harici bağımlılıklar (ağ, disk, nmap) monkeypatch ile izole edilebilir
- **PEP-8 Uyumlu:** flake8 ile 0 hata doğrulandı
