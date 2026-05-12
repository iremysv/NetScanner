# -*- coding: utf-8 -*-

# Nmap Tarama Hızı (T3: Normal, T4: Hızlı, T5: Agresif)
TARAMA_HIZI = "-T4"

# Varsayılan Rapor Klasörü
RAPOR_DIZINI = "taramalar"

# Versiyon ve OS Tespiti bayrakları
DETAYLI_MOD = "-sV -O"

# Trafik Analizi ve Anomali Eşik Değerleri
PORT_SCAN_THRESHOLD = 15        # Bir IP'nin kısa sürede taradığı farklı port sayısı sınırı
DNS_TUNNELING_THRESHOLD = 50    # Kısa sürede aşırı DNS isteği yapma sınırı
SYN_FLOOD_THRESHOLD = 100       # Bir IP'nin cevap almadan gönderdiği SYN paket sayısı
ARP_SPOOF_THRESHOLD = 5         # Aynı IP için farklı MAC adreslerinden gelen ARP sayısı
LARGE_PAYLOAD_THRESHOLD = 50000 # Bayt cinsinden tek seferde giden aşırı büyük veri boyutu (Data Exfiltration)
TRAFIK_RAPOR_DIZINI = "taramalar/traffic_reports"

