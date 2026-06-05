# 🔬 Araştırma ve Geliştirme Süreci (Research & Learnings)

Bu klasör, **NetScanner (NetSentry)** projesinin geliştirilme aşamasındaki araştırma süreçlerini, karşılaşılan teknik zorlukları, girilen çıkmaz sokakları ve bu süreçten elde edilen kazanımları belgelemek amacıyla oluşturulmuştur.

---

## 📌 1. Araştırma ve Teknoloji Seçimi

Projenin başlangıcında, temel isterleri karşılamak üzere farklı kütüphane ve teknolojiler karşılaştırılmıştır:

### A. Paket Yakalama ve Sniffing Motoru: Scapy vs. Socket vs. PyPCAP
* **Raw Sockets:** C düzeyinde performans sunmasına rağmen, paketlerin el ile parse edilmesi (IP, TCP, UDP başlıklarının bit düzeyinde kaydırılması) geliştirme süresini aşırı uzatacaktı.
* **PyPCAP:** Hızlı ve hafif bir C kütüphanesi sarmalayıcısıdır ancak esnek filtreleme ve paket enjeksiyon özellikleri zayıftır.
* **Scapy (Seçilen):** Paket analizinde endüstri standardıdır. HTTP, DNS, TCP, UDP gibi yüzlerce protokolü otomatik çözebilmesi ve esnek filtreleme (`BPF syntax`) desteği sunması nedeniyle tercih edilmiştir. Performans kaygıları, arka planda hafif thread yapıları ve paket filtreleri kullanılarak optimize edilmiştir.

### B. Web Arayüzü: FastAPI vs. Flask
* **Flask:** Geleneksel ve kararlı bir yapı sunar ancak asenkron (async/await) mimarileri ve WebSocket yapısını yerleşik olarak desteklemez.
* **FastAPI (Seçilen):** Gerçek zamanlı paket akışını web arayüzüne taşımak için yüksek performanslı WebSocket desteği, pydantic ile otomatik veri doğrulama ve asenkron yapısı sayesinde tercih edilmiştir.

---

## 🚧 2. Çıkmaz Sokaklar ve Karşılaşılan Teknik Engeller (Dead Ends)

Geliştirme sürecinde karşılaşılan ve mimari değişiklik gerektiren kritik problemler şunlardır:

### ⚠️ Çıkmaz Sokak 1: Yetki Sınırları ve İzin Hataları (Privilege Elevation)
* **Sorun:** Canlı ağ trafiğini dinleme (`scapy.sniff()`) ve Nmap'in gelişmiş tarama modlarını (İşletim Sistemi Analizi `-O`, Agresif Tarama `-A`) çalıştırma işlemleri, işletim sistemlerinde doğrudan **root/yönetici yetkisi** gerektirmektedir. İlk prototipte root yetkisi olmadan çalıştırılan taramalar `PermissionError` (Soket oluşturulamadı hatası) ile çökmekteydi.
* **Çıkmaz Yol:** Uygulamayı tamamen root yetkileriyle çalıştırmak güvenlik zafiyeti doğurmaktadır.
* **Çözüm/Aşım:** 
  - CLI arayüzünde canlı dinleme yapılmak istendiğinde kullanıcının işletim sistemine göre `sudo` ile çalıştırması gerektiği uyarısı eklendi.
  - Kod blokları `PermissionError` ve `OSError` durumlarını yakalayacak şekilde sarmalandı. Yetkisiz çalıştırma durumunda sistem çökmek yerine kullanıcıya anlaşılır hata logları üretmektedir.

### ⚠️ Çıkmaz Sokak 2: Yüksek Trafik Altında Thread Kilitlenmeleri (Race Conditions)
* **Sorun:** Canlı sniffer arka planda paketleri yakalayıp paylaşılan bir listeye yazarken, WebSocket sunucusu bu listeyi okuyup arayüze gönderiyordu. Yüksek trafikli ağlarda aynı bellek bölgesine aynı anda okuma-yazma yapılması nedeniyle `RuntimeError: dictionary changed size during iteration` hataları ve kilitlenmeler yaşandı.
* **Çıkmaz Yol:** Basit Python listeleri asenkron okuma/yazma işlemleri için güvenli değildir.
* **Çözüm/Aşım:**
  - Paylaşılan bellek bölgeleri için `threading.Lock` nesnesi kullanılarak senkronizasyon sağlandı.
  - Veri transferinde thread-safe (iş parçacığı güvenli) veri yapıları ve kuyruk mekanizmaları entegre edildi.

### ⚠️ Çıkmaz Sokak 3: DNS Tünelleme (DNS Tunneling) Tespitindeki Yanlış Alarmlar (False Positives)
* **Sorun:** İlk tünelleme tespit algoritması, sadece alan adı boyutunu (subdomain length) kontrol ediyordu. Ancak CDN (Content Delivery Network) servisleri, karmaşık API uç noktaları ve bazı güvenlik yazılımları meşru amaçlarla çok uzun alt alan adları kullanmaktadır. Bu durum sistemin sürekli yanlış alarm üretmesine neden oldu.
* **Çıkmaz Yol:** Sadece subdomain uzunluğuna bakarak alarm üretmek sistemi kullanılamaz hale getirmiştir.
* **Çözüm/Aşım:**
  - Tespit motoruna çoklu metrik analiz entegre edildi. Artık sadece uzunluğa değil; subdomain karakterlerinin **entropisine** (rastgelelik derecesine) ve bir IP adresinin belirli bir sürede yaptığı **istek sıklığına (rate)** bakılarak analiz yapılmaktadır.

---

## 💡 3. Öğrenilen Dersler ve Kazanımlar

Bu proje sayesinde elde edilen önemli akademik ve teknik kazanımlar:

1. **Ağ Protokollerinin Derinlemesine Analizi:** TCP/IP katman yapısı, TCP üçlü el sıkışması (SYN-SYNACK-ACK) ve DNS sorgularının yapısal anatomisi teoriden pratiğe dökülerek pekiştirilmiştir.
2. **Asenkron Web Programlama:** Gerçek zamanlı veri akışlarında (WebSocket) sunucu ve istemci arasındaki eşzamanlı iletişimin yönetilmesi, veri kaybının önlenmesi deneyimlenmiştir.
3. **Güvenli Kodlama ve Hata Yönetimi:** Subprocess çağrıları, dosya yükleme (PCAP) işlemleri ve harici API entegrasyonlarında savunmacı programlama (defensive programming) prensipleri uygulanarak sistem dayanıklılığı artırılmıştır.
