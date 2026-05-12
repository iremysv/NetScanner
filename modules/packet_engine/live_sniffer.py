import logging
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("LiveSniffer")


class LiveSniffer:
    """
    Canlı ağ trafiğini dinlemek (sniffing) ve yakalanan paketleri
    anlık olarak ayrıştırmakla görevli sınıf. Arka planda çalışması için
    threading kullanır.
    """

    def __init__(self):
        self.parsed_packets = []
        self._stop_event = threading.Event()
        self._sniff_thread = None

    def _packet_handler(self, pkt):
        """
        Scapy tarafından yakalanan her bir paket için çağrılan callback fonksiyonu.
        Paketi ayrıştırır ve self.parsed_packets listesine ekler.
        """
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            length = len(pkt)

            protocol = "OTHER"
            src_port = 0
            dst_port = 0

            flags = ""
            payload_data = None
            dns_query = None

            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags
                if src_port == 80 or dst_port == 80:
                    protocol = "HTTP"
                    if Raw in pkt:
                        try:
                            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                            if "HTTP" in raw_data or "GET " in raw_data or "POST " in raw_data:
                                payload_data = raw_data[:200]
                        except:
                            pass
                elif src_port == 443 or dst_port == 443:
                    protocol = "HTTPS"
                elif src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                else:
                    protocol = "TCP"
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                if src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                else:
                    protocol = "UDP"
            elif ICMP in pkt:
                protocol = "ICMP"

            # DPI: DNS Sorgularının Çıkarılması
            if DNS in pkt and DNSQR in pkt:
                try:
                    dns_query = pkt[DNSQR].qname.decode('utf-8')
                except:
                    pass

            parsed_data = {
                "src_ip": ip_src,
                "dst_ip": ip_dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "flags": str(flags),
                "payload_preview": payload_data,
                "dns_query": dns_query
            }

            self.parsed_packets.append(parsed_data)

    def _sniff_worker(self, interface=None):
        """Arka planda sniffing işlemini yürüten iş parçacığı (worker) fonksiyonu."""
        try:
            logger.info(f"Canlı ağ dinlemesi başlatıldı. Arayüz: {interface if interface else 'Otomatik Seçim'}")
            # stop_filter, _stop_event True olunca sniffing'i durdurur
            sniff(iface=interface, prn=self._packet_handler, stop_filter=lambda p: self._stop_event.is_set(), store=False)
        except Exception as e:
            if "Permission" in str(e) or "root" in str(e):
                logger.error("Sniffing için yeterli izin yok. Lütfen programı yönetici (sudo) haklarıyla çalıştırın.")
            else:
                logger.error(f"Sniffing sırasında beklenmeyen bir hata oluştu: {e}")

    def start_sniffing(self, interface=None):
        """
        Dinleme işlemini arka planda (thread) başlatır.
        """
        if self._sniff_thread and self._sniff_thread.is_alive():
            logger.warning("Sniffing zaten çalışıyor.")
            return

        self._stop_event.clear()
        self.parsed_packets = []
        self._sniff_thread = threading.Thread(target=self._sniff_worker, args=(interface,), daemon=True)
        self._sniff_thread.start()

    def stop_sniffing(self):
        """
        Dinleme işlemini durdurur.
        """
        if self._sniff_thread and self._sniff_thread.is_alive():
            logger.info("Canlı ağ dinlemesi durduruluyor...")
            self._stop_event.set()
            self._sniff_thread.join()
            logger.info(f"Dinleme durduruldu. Toplam {len(self.parsed_packets)} paket yakalandı.")
        else:
            logger.warning("Durdurulacak aktif bir sniffing işlemi bulunamadı.")

    def get_parsed_packets(self):
        """
        Yakalanan ve ayrıştırılan paketlerin listesini döndürür.
        """
        return self.parsed_packets
