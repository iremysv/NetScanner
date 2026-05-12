import os
import logging
from scapy.all import rdpcap, Scapy_Exception, IP, TCP, UDP, ICMP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Logging ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PcapReader")


class PcapReader:
    """
    .pcap ve .pcapng uzantılı ağ trafiği dosyalarını okumak ve
    içerisindeki paketleri analiz için hazırlamakla görevli sınıf.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.packets = []

    def read_pcap(self):
        """
        Belirtilen PCAP dosyasını okur ve paketleri belleğe alır.
        Başarılı olursa True, başarısız olursa False döndürür.
        """
        if not os.path.exists(self.file_path):
            logger.error(f"Dosya bulunamadı: {self.file_path}")
            return False

        logger.info(f"PCAP dosyası okunuyor: {self.file_path} ... Lütfen bekleyin.")

        try:
            # Scapy ile PCAP dosyasını oku
            self.packets = rdpcap(self.file_path)
            logger.info(f"Başarıyla okundu. Toplam paket sayısı: {len(self.packets)}")
            return True

        except Scapy_Exception as e:
            logger.error(f"PCAP okuma hatası (Scapy kaynaklı): {e}")
            return False
        except Exception as e:
            logger.error(f"Beklenmeyen bir hata oluştu: {e}")
            return False

    def get_packets(self):
        """Okunan paketlerin listesini döndürür."""
        return self.packets

    def parse_packets(self):
        """
        Okunan paketlerin içerisinden Kaynak/Hedef IP, Port, Protokol
        ve Veri Boyutu gibi bilgileri ayrıştırır (parse eder).
        """
        if not self.packets:
            logger.warning("Ayrıştırılacak paket bulunamadı. Lütfen önce read_pcap() çalıştırın.")
            return []

        parsed_data = []
        logger.info("Paketler ayrıştırılıyor...")

        for pkt in self.packets:
            if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                length = len(pkt)

                protocol = "OTHER"
                src_port = 0
                dst_port = 0

                if TCP in pkt:
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    protocol = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                elif ICMP in pkt:
                    protocol = "ICMP"

                parsed_data.append({
                    "src_ip": ip_src,
                    "dst_ip": ip_dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "length": length
                })

        logger.info(f"Başarıyla {len(parsed_data)} paket IP katmanında ayrıştırıldı.")
        return parsed_data
