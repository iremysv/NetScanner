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
