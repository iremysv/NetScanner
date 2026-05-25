# -*- coding: utf-8 -*-
import asyncio
import os
import re
import tempfile
from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    File,
    UploadFile,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator

# Mevcut modüller
from modules.nmap_integration.scanner import nmap_calistir
from modules.packet_engine.pcap_reader import PcapReader
from modules.packet_engine.traffic_analyzer import TrafficAnalyzer
from modules.packet_engine.live_sniffer import LiveSniffer
from reports.traffic_reporter import trafik_raporu_olustur
from reports.markdown_reporter import markdown_guvenlik_raporu_olustur

app = FastAPI(title="NetScanner Web Dashboard")

# Statik dosyalar ve şablonlar
app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")

# Analiz Motoru ve Sniffer
analyzer = TrafficAnalyzer([])
live_sniffer = LiveSniffer()


# WebSocket bağlantılarını yönetecek sınıf
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.active_connections.remove(conn)


manager = ConnectionManager()


# Ana Sayfa (Dashboard)
@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse(
        request=request, name="index.html", context={"request": request}
    )

# Tarama İstek Modeli
_ALLOWED_SCAN_TYPES = {"quick", "discovery", "service", "os", "aggressive", "vuln"}
_TARGET_PATTERN = re.compile(
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}"           # IPv4: 192.168.1.1
    r"|(\d{1,3}\.){3}\d{1,3}/\d{1,2}"  # CIDR: 192.168.1.0/24
    r"|([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"  # Alan adı: example.com
    r")$"
)


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Hedef IP veya alan adı boş olamaz.")
        if not _TARGET_PATTERN.match(v):
            raise ValueError(
                f"Geçersiz hedef formatı: '{v}'. "
                "IPv4, CIDR veya alan adı giriniz."
            )
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in _ALLOWED_SCAN_TYPES:
            raise ValueError(
                f"Geçersiz tarama tipi: '{v}'. "
                f"İzin verilenler: {_ALLOWED_SCAN_TYPES}"
            )
        return v


# Nmap Tarama API
@app.post("/api/scan")
async def run_scan(req: ScanRequest):
    hedef = req.target
    if req.scan_type == "quick":
        komut_listesi = ["nmap", "-T4", "-F", hedef]
    elif req.scan_type == "discovery":
        komut_listesi = ["nmap", "-T4", "-sn", hedef]
    elif req.scan_type == "service":
        komut_listesi = ["nmap", "-T4", "-sV", hedef]
    elif req.scan_type == "os":
        komut_listesi = ["sudo", "nmap", "-T4", "-O", hedef]
    elif req.scan_type == "aggressive":
        komut_listesi = ["sudo", "nmap", "-T4", "-A", hedef]
    elif req.scan_type == "vuln":
        komut_listesi = ["nmap", "-sV", "--script=vuln", hedef]
    else:
        raise HTTPException(status_code=400, detail="Geçersiz tarama tipi.")

    # WebSocket ile anlık "Başladı" mesajı
    await manager.broadcast(
        {"type": "info", "message": f"{hedef} için {req.scan_type} tarama başlatılıyor..."}
    )

    loop = asyncio.get_running_loop()
    sonuc_text, rapor_yolu = await loop.run_in_executor(
        None, nmap_calistir, komut_listesi, hedef, f"web_scan_{hedef}"
    )

    if sonuc_text:
        return {
            "status": "success",
            "result": sonuc_text,
            "report_path": rapor_yolu,
        }
    return {"status": "error", "message": "Tarama başarısız oldu."}


# Canlı Sistem Metrikleri & Log Akışı (WebSocket)
@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        last_packet_count = 0
        while True:
            await asyncio.sleep(2)
            if live_sniffer._sniff_thread and (
                live_sniffer._sniff_thread.is_alive()
            ):
                current_packets = live_sniffer.get_parsed_packets()
                current_count = len(current_packets)
                if current_count > last_packet_count:
                    new_packets = current_packets[
                        last_packet_count:current_count
                    ]
                    last_packet_count = current_count

                    # Son 5 paketin özetini arayüze canlı yansıtmak için
                    latest_previews = [
                        (
                            f"[{p['protocol']}] {p['src_ip']} -> "
                            f"{p['dst_ip']} ({p['length']} byte)"
                        )
                        for p in new_packets[-5:]
                    ]

                    await websocket.send_json(
                        {
                            "type": "live_traffic",
                            "count": current_count,
                            "latest": latest_previews,
                        }
                    )
                else:
                    await websocket.send_json(
                        {
                            "type": "live_traffic",
                            "count": current_count,
                            "latest": [],
                        }
                    )
            else:
                last_packet_count = 0
                await websocket.send_json({"type": "ping", "message": "Alive"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Canlı Dinleme (Live Sniffing) Başlatma API
@app.post("/api/sniff/start")
async def start_sniffing():
    if live_sniffer._sniff_thread and (
        live_sniffer._sniff_thread.is_alive()
    ):
        return {"status": "error", "message": "Canlı izleme zaten çalışıyor."}

    live_sniffer.start_sniffing()
    await manager.broadcast(
        {
            "type": "info",
            "message": (
                "Canlı paket dinlemesi arka planda başlatıldı."
            ),
        }
    )
    return {"status": "success", "message": "Canlı izleme başlatıldı."}


# Canlı Dinleme (Live Sniffing) Durdurma ve Analiz API
@app.post("/api/sniff/stop")
async def stop_sniffing():
    if not live_sniffer._sniff_thread or not (
        live_sniffer._sniff_thread.is_alive()
    ):
        return {
            "status": "error",
            "message": "Çalışan bir canlı izleme işlemi bulunamadı.",
        }

    live_sniffer.stop_sniffing()
    paketler = live_sniffer.get_parsed_packets()

    if not paketler:
        return {
            "status": "success",
            "message": (
                "Dinleme durduruldu. "
                "Herhangi bir ağ paketi yakalanamadı."
            ),
            "data": {},
        }

    analyzer_instance = TrafficAnalyzer(paketler)
    sonuclar = analyzer_instance.analyze()
    trafik_raporu_olustur("web_live_sniff", sonuclar)
    markdown_guvenlik_raporu_olustur(
        hedef="Canli_Ag",
        trafik_sonuclar=sonuclar,
        connection_map=sonuclar.get("connection_map"),
    )

    await manager.broadcast(
        {
            "type": "success",
            "message": (
                f"Canlı izleme durduruldu. Toplam {len(paketler)} "
                f"paket yakalandı ve analiz edildi."
            ),
        }
    )
    return {
        "status": "success",
        "data": sonuclar,
        "message": "Analiz başarıyla tamamlandı.",
    }


# PCAP Dosya Yükleme ve Analiz API
@app.post("/api/pcap_upload")
async def upload_pcap(file: UploadFile = File(...)):
    # Dosya uzantısı kontrolü
    filename = file.filename or ""
    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail=(
                "Sadece .pcap veya .pcapng uzantılı dosyalar "
                "kabul edilmektedir."
            ),
        )

    await manager.broadcast(
        {
            "type": "info",
            "message": (
                f"'{filename}' dosyası sisteme"
                " yüklüniyor ve analiz ediliyor..."
            ),
        }
    )

    content = await file.read()

    # Güvenli geçici dosya — isim enjeksiyonuna karşı NamedTemporaryFile kullan
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(content)
            temp_pcap_path = tmp.name

        # PcapReader ile oku ve analiz et
        reader = PcapReader(temp_pcap_path)
        if reader.read_pcap():
            paketler = reader.parse_packets()
            analyzer_instance = TrafficAnalyzer(paketler)
            sonuclar = analyzer_instance.analyze()

            if not sonuclar:
                return {
                    "status": "error",
                    "message": (
                        "PCAP dosyası analiz edilemedi veya "
                        "desteklenen paket bulunamadı."
                    ),
                }

            trafik_raporu_olustur("web_pcap", sonuclar)
            markdown_guvenlik_raporu_olustur(
                hedef=filename,
                trafik_sonuclar=sonuclar,
                connection_map=sonuclar.get("connection_map"),
            )
            await manager.broadcast(
                {
                    "type": "success",
                    "message": f"'{filename}' analizi tamamlandı.",
                }
            )
            return {
                "status": "success",
                "data": sonuclar,
                "message": "Analiz başarıyla tamamlandı.",
            }
        else:
            return {
                "status": "error",
                "message": "PCAP dosyası okunamadı veya geçersiz.",
            }

    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if "temp_pcap_path" in locals() and os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)
