# 📖 NetScanner: 50 Adımda Ağ Analizi ve Tehdit Algılama Kılavuzu

Bu kılavuz, **NetScanner** platformunun temel çalışma mantığını, ağ güvenliği kavramlarını ve sistem mimarisini 50 adımda kolaydan karmaşığa doğru açıklamaktadır.

---

## 📌 Bölüm 1: Temel Kavramlar (Adım 1-8)

1. **Ağ İletişimi**: Bilgisayarlar ağ üzerinde veri alışverişi yaparken bilgileri küçük paketlere bölerek iletirler. Her bilgisayarın ağda kendini temsil eden benzersiz bir **IP adresi** bulunur.
2. **Ağ Paketi**: Ağ üzerinden gönderilen her veri birimine paket denir. Paketler iki ana kısımdan oluşur: Yönlendirme bilgilerini içeren **Header (Üstbilgi)** ve asıl taşınan veriyi içeren **Payload (Yük)**.
3. **Protokoller**: İletişimin kurallarını belirleyen standartlardır. Örneğin; veri iletimi için **TCP** ve **UDP**, alan adlarını IP adreslerine çevirmek için **DNS**, web sayfalarını yüklemek için **HTTP** kullanılır.
4. **Port Kavramı**: Bir bilgisayarda çalışan servislerin dış dünyaya açılan kapılarıdır. 1 ile 65535 arasında numaralandırılırlar. Örneğin; HTTP varsayılan olarak `80`, HTTPS `443`, SSH ise `22` portunu kullanır.
5. **Soket (Socket) Programlama**: Bir IP adresi ve bir port numarasının birleşiminden oluşan, iki bilgisayar arasındaki veri akış kanalını yöneten programlama arayüzüdür. NetScanner bu soketleri dinleyerek çalışır.
6. **TCP 3'lü El Sıkışması**: TCP bağlantısı kurulurken güvenli iletim için sırasıyla **SYN** (Bağlantı isteği), **SYN-ACK** (Onay ve istek) ve **ACK** (Onay) paketleri gönderilir.
7. **Ağ Arayüzü (Interface)**: Bilgisayarınızın ağa bağlanan fiziksel (örn. `eth0`, `en0`) veya sanal (örn. `lo0` - localhost) donanım kartlarıdır. Canlı ağ dinlemeleri bu arayüzler üzerinden yapılır.
8. **Karışık Mod (Promiscuous Mode)**: Ağ kartının, normalde sadece kendi bilgisayarına gelen paketleri kabul etmek yerine, ağdaki tüm paketleri okumasını sağlayan moddur. Canlı paket yakalama için bu modun açılması şarttır.

---

## 📡 Bölüm 2: Nasıl Çalışır? (Adım 9-16)

9. **Sistem Mimarisi**: NetScanner iki sunum katmanına sahiptir: Hızlı işlemler için **CLI (main.py)** ve görsel analizler için **Web Dashboard (FastAPI + WebSocket)**.
10. **PCAP Dosyaları**: Ağ arayüzünden geçen paketlerin `.pcap` veya `.pcapng` formatında diske kaydedilmiş halidir. Geçmişe dönük adli analizlerde (forensics) delil olarak kullanılır.
11. **pcap_reader.py**: NetScanner içindeki bu modül, Python'ın gelişmiş ağ kütüphanesi **Scapy**'yi kullanarak ham PCAP dosyalarını okur ve Python veri yapılarına (sözlüklere) dönüştürür.
12. **Paket Ayrıştırma**: Okunan ham paketlerin içindeki kaynak IP (`src_ip`), hedef IP (`dst_ip`), portlar, protokol türleri ve paket boyutları tek tek ayrıştırılarak analiz motoruna hazır hale getirilir.
13. **Canlı İzleme (Sniffing)**: Sistem aktifken ağ kartından geçen verileri anlık olarak dinleme işlemidir. Arka planda ana programı kilitlememesi için **Python Threading** (iş parçacığı) yapısı kullanılır.
14. **live_sniffer.py**: Ağ arayüzünü sürekli dinleyen ve yakalanan her paketi anında arayüze ileten bileşendir. Scapy'nin `sniff()` fonksiyonu ve asenkron callback yapısı ile çalışır.
15. **Nmap Entegrasyonu**: Ağdaki aktif cihazları, açık portları ve bu portlarda çalışan servislerin versiyonlarını keşfetmek amacıyla endüstri standardı olan Nmap aracını entegre eder.
16. **scanner.py**: Python'ın `subprocess` modülünü kullanarak arka planda Nmap komutlarını çalıştırır, çıktısını yakalar ve `taramalar/` dizinine rapor halinde kaydeder.

---

## 🛡️ Bölüm 3: Anomali Nedir? (Adım 17-25)

17. **Anomali Tespiti**: Ağ trafiğinde normalin dışına çıkan, şüpheli veya zararlı olabilecek hareket modellerinin (pattern) tespit edilmesidir.
18. **SYN Flood (DDoS)**: Saldırganın, hedef sunucuya sürekli bağlantı isteği (SYN) gönderip, sunucunun cevabına (SYN-ACK) onay (ACK) göndermeyerek sunucu kaynaklarını tüketmesidir.
19. **SYN Flood Yakalama**: NetScanner, gelen paketlerde sadece `SYN` bayrağı taşıyan ve `ACK` bayrağı taşımayan paketleri sayar. Bir IP'den gelen SYN sayısı belirlenen eşiği aşarsa alarm üretir.
20. **Port Tarama (Port Scan)**: Saldırganın, hedef sistemde hangi kapıların (portların) açık olduğunu bulmak için sırayla veya rastgele yüzlerce porta paket göndermesidir.
21. **Port Tarama Yakalama**: NetScanner, tek bir kaynak IP'nin kısa bir süre içinde kaç farklı benzersiz hedef porta bağlandığını sayar. Bu sayı eşik değerini aşarsa "PORT_SCAN" anomalisi raporlanır.
22. **DNS Tünelleme (DNS Tunneling)**: Saldırganın, şirket ağındaki güvenlik önlemlerini (firewall, proxy) aşmak için çalınan verileri DNS isteklerinin içine (subdomain olarak) gizleyerek dışarı sızdırmasıdır.
23. **DNS Tünelleme Yakalama**: NetScanner, bir kaynak IP'nin attığı DNS isteklerinin sıklığını takip eder. Kısa sürede anormal miktarda DNS isteği gönderilmesi durumunda uyarı verir.
24. **Derin Paket İnceleme (DPI)**: Sadece paket başlıklarına (IP, Port) bakmakla yetinmeyip, paketin payload (veri) kısmının içeriğini de tarayarak zararlı kod arama işlemidir.
25. **DNS DPI Anomalisi**: NetScanner, DNS isteklerindeki sorgu adının (domain) uzunluğunu kontrol eder. Eğer sorgu adı 50 karakterden uzunsa (örn. `base64_veri.saldirgan.com`), bunu DNS DPI anomalisi olarak işaretler.

---

## 📊 Bölüm 4: Hangi Bilgiler Toplanır? (Adım 26-33)

26. **Top Talkers**: Ağ üzerinde en fazla veri gönderen ve alan, dolayısıyla ağ bandını en çok meşgul eden ilk 10 aktif IP adresidir.
27. **IP Konumlandırma (GeoIP)**: İnternet üzerindeki harici IP adreslerinin hangi ülkeye ve şehre ait olduğunu belirleme işlemidir. Tehdidin coğrafi kaynağını anlamaya yardımcı olur.
28. **OSINT ve ip-api.com**: NetScanner, harici IP adreslerini konumlandırmak için açık kaynak istihbaratı (OSINT) kapsamında `ip-api.com` web servisine sorgular gönderir.
29. **GeoIP Önbelleği (Cache)**: Aynı IP adresini tekrar tekrar sorgulamamak ve harici API limitlerini aşmamak için sorgulanan IP'lerin konum bilgileri hafızada (cache) saklanır.
30. **Yerel IP'lerin Ayrıştırılması**: RFC 1918 standartlarındaki özel IP blokları (örn. `192.168.x.x`, `10.x.x.x`, `127.0.0.1`) GeoIP sorgusuna gönderilmez, doğrudan "Yerel Ağ (Local)" olarak işaretlenir.
31. **Protokol Dağılımı**: Yakalanan tüm paketler arasında hangi protokolün (HTTP, HTTPS, DNS, TCP vb.) yüzde kaçlık bir paya sahip olduğunu gösteren istatistiksel veridir.
32. **Veri Sızdırma (Data Exfiltration)**: Ağ dışına büyük dosya çıkarılmasını yakalamak için NetScanner, paket boyutlarını (`length`) inceler. Eşik değerden (varsayılan 50KB) büyük paketleri şüpheli transfer olarak kaydeder.
33. **HTTP Malicious Payload**: HTTP trafiğinde paket içeriği taranır. Payload kısmında `sql` (SQL Injection), `script` (XSS) veya `curl` (otomatik bot) gibi şüpheli anahtar kelimeler geçerse anomali listesine eklenir.

---

## 🚧 Bölüm 5: Nasıl Korunuruz? (Adım 34-42)

34. **Dedektif Mantığı ve Tutuklama**: Ağ trafiğinde şüpheliyi bulduktan sonra (Tespit), ağa zarar vermesini engellemek için güvenlik duvarı kuralları ile engelleme (Tutuklama) adımı uygulanır.
35. **Güvenlik Duvarı (Firewall)**: Belirlenen kurallara göre ağ trafiğini geçiren veya engelleyen ilk savunma hattıdır. Yazılımsal veya donanımsal olabilir.
36. **Saldırgan IP'yi Engelleme**: Tespit edilen zararlı IP adreslerinin sisteme veya ağa erişimini tamamen kesmek için işletim sistemi düzeyinde engelleme kuralları yazılır.
37. **iptables Kuralı Yazma**: Linux sistemlerde bir IP'yi engellemek için terminale yazılan komuttur:
   ```bash
   sudo iptables -A INPUT -s [SALDIRGAN_IP] -j DROP
   ```
38. **TCP SYN Cookies**: SYN Flood DDoS saldırılarına karşı sunucunun hafızasını korumak amacıyla, sunucunun bağlantı durumunu hafızada tutmak yerine paket içine şifreli (cookie) yazması yöntemidir.
39. **Port Taramasından Korunma**: Kullanılmayan tüm portlar kapatılmalı, açık portlar ise sadece belirli güvenilir IP adreslerine (Whitelisting) izin verecek şekilde yapılandırılmalıdır.
40. **DNS Filtreleme**: Şirket ağında sadece yetkilendirilmiş DNS sunucularına izin verilmeli, diğer tüm DNS portları (Port 53) kapatılarak DNS tünelleme engellenmelidir.
41. **WAF (Web Application Firewall)**: HTTP paketlerini uygulama katmanında inceleyerek SQL Injection ve XSS gibi payload içeren saldırıları web sunucusuna ulaşmadan engeller.
42. **Sıfır Güven (Zero Trust)**: "Asla güvenme, her zaman doğrula" prensibidir. Ağın içindeki cihazların bile her an ele geçirilebileceğini varsayarak her bağlantıda kimlik doğrulama ister.

---

## 📋 Bölüm 6: Proje Notları & Özet (Adım 43-50)

43. **Modüler Tasarım**: NetScanner'ın analiz motoru (`TrafficAnalyzer`) ile veri toplama motoru (`LiveSniffer`/`PcapReader`) tamamen ayrıdır. Bu sayede sisteme yeni bir analiz kuralı eklemek oldukça kolaydır.
44. **CLI ve Web Entegrasyonu**: CLI doğrudan sunucu terminallerinde hızlıca tarama yapmak için idealken, Web Dashboard yöneticilerin grafikleri ve canlı akışı izlemesini kolaylaştırır.
45. **WebSocket Teknolojisi**: Tarayıcının sürekli istek atıp sunucuyu yorması yerine, sunucunun yakaladığı yeni paketleri tarayıcıya anında itmesini (push) sağlayan çift yönlü iletişim kanalıdır.
46. **Sahte Veri (Dummy Data) Testleri**: Gerçek bir saldırı gerçekleştirmeden tespit motorunu test etmek için anomali içeren sentetik ağ trafik dosyaları üretilir.
47. **generate_dummy.py**: Projede yer alan bu script; içinde SYN Flood, Port Tarama ve DNS Tünelleme aktiviteleri barındıran yapay bir `dummy.pcap` dosyası oluşturur ve testlerin doğruluğunu kanıtlar.

48. **Normal ve Şüpheli Trafik Karşılaştırma Tablosu**:

| Özellik | Normal Trafik Modeli | Şüpheli/Anormal Trafik Modeli |
| :--- | :--- | :--- |
| **SYN / ACK Oranı** | Yaklaşık 1:1 (Her isteğe bir yanıt) | Sadece SYN paketleri yığılması (ACK yok) |
| **Erişilen Port Sayısı** | Sadece gerekli servis portları (80, 443 vb.) | Tek bir IP'den kısa sürede onlarca benzersiz porta erişim |
| **DNS Sorgu Yapısı** | Kısa ve anlamlı alan adları (`google.com`) | Aşırı uzun ve anlamsız alt alan adları (DPI Anomali) |
| **Paket Boyutları** | Protokol standartlarına uygun boyutlar | Anormal büyüklükte tekil yükler (Veri sızdırma) |

49. **Polis Dedektifi Mantığıyla NetScanner Rol Dağılımı**:

| Dedektif Terimi | Ağ Güvenliği Karşılığı | NetScanner'daki Karşılığı |
| :--- | :--- | :--- |
| **Olay Yeri** | Ağ Arayüzü / Kartı | `live_sniffer.py` üzerinden dinlenen arayüz (`eth0`/`en0`) |
| **Delil** | Ham Ağ Paketleri | Scapy ile yakalanan veya PCAP dosyasından okunan byte'lar |
| **Tercüman** | Paket Ayrıştırıcı | `PcapReader` / Paketleri anlaşılır JSON/Sözlük formatına çeviren motor |
| **Kanıt** | Tespit Edilen Anomaliler | `TrafficAnalyzer` (SYN Flood, Port Scan, DNS Tunneling tespitleri) |
| **Tutuklama** | Saldırıyı Durdurma | Rapor çıktısı ve firewall/iptables engelleme kuralları oluşturma |

50. **Son Söz**: Ağ güvenliği statik bir durum değil, dinamik bir süreçtir. NetScanner gibi araçlar ağdaki gözünüz ve kulağınızdır; ancak en önemli bileşen, **arka plandaki mantığı anlayan eğitimli siber güvenlik uzmanıdır.**
