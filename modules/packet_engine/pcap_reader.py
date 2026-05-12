import os
import logging
from tqdm import tqdm
from scapy.all import PcapReader as ScapyPcapReader, Scapy_Exception, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Logging ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PcapReader")

class PcapReader:
    """
    .pcap ve .pcapng uzantılı ağ trafiği dosyalarını okumak ve
    içerisindeki paketleri analiz için hazırlamakla görevli sınıf.
    Büyük dosyalar için iteratif okuma (Progress Bar ile) ve DPI (Derin Paket İnceleme) destekler.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.parsed_data = []
        self._read_success = False

    def read_pcap(self):
        """
        Belirtilen PCAP dosyasını iteratif (parça parça) okur ve aynı anda ayrıştırır.
        Bellek dostudur.
        """
        if not os.path.exists(self.file_path):
            logger.error(f"Dosya bulunamadı: {self.file_path}")
            return False

        logger.info(f"PCAP dosyası DPI (Derin İnceleme) ile okunuyor: {self.file_path} ... Lütfen bekleyin.")
        file_size = os.path.getsize(self.file_path)

        try:
            # PcapReader ile iteratif okuma
            with ScapyPcapReader(self.file_path) as pcap_reader:
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="PCAP İşleniyor") as pbar:
                    for pkt in pcap_reader:
                        # pkt.wirelen bize paketin tahmini bayt boyutunu verir
                        pkt_len = pkt.wirelen if hasattr(pkt, 'wirelen') else len(pkt)
                        pbar.update(pkt_len)
                        
                        # Anında Parse Et (Bellek Tasarrufu)
                        parsed_pkt = self._extract_packet_info(pkt)
                        if parsed_pkt:
                            self.parsed_data.append(parsed_pkt)

            logger.info(f"Başarıyla okundu ve ayrıştırıldı. Toplam paket sayısı: {len(self.parsed_data)}")
            self._read_success = True
            return True

        except Scapy_Exception as e:
            logger.error(f"PCAP okuma hatası (Scapy kaynaklı): {e}")
            return False
        except Exception as e:
            logger.error(f"Beklenmeyen bir hata oluştu: {e}")
            return False

    def get_packets(self):
        """Geriye dönük uyumluluk için (aslında parse edilmiş veriyi döner)."""
        return self.parsed_data

    def parse_packets(self):
        """
        Okuma işlemi sırasında zaten ayrıştırıldığı için,
        sadece hazırlanan veriyi döndürür.
        """
        if not self._read_success:
            logger.warning("Ayrıştırılacak paket bulunamadı. Lütfen önce read_pcap() çalıştırın.")
            return []
        return self.parsed_data

    def _extract_packet_info(self, pkt):
        """
        Tek bir paketten kaynak/hedef, port ve Payload (DPI) bilgilerini çıkarır.
        """
        if IP not in pkt:
            return None

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
                        # HTTP User-Agent veya URL çıkartmayı deneyelim
                        raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                        if "HTTP" in raw_data or "GET " in raw_data or "POST " in raw_data:
                            payload_data = raw_data[:200] # İlk 200 karakteri sakla
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

        return {
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
