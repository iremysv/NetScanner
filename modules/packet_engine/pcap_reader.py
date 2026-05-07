import os
import logging
from scapy.all import rdpcap, Scapy_Exception

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
