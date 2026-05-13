# -*- coding: utf-8 -*-
import asyncio
import json
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Mevcut modüller
from core import config as Ayarlar
from modules.nmap_integration.scanner import nmap_calistir
from modules.packet_engine.traffic_analyzer import TrafficAnalyzer
from reports.traffic_reporter import trafik_raporu_olustur

app = FastAPI(title="NetScanner Web Dashboard")

# Statik dosyalar ve şablonlar
app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")

# Analiz Motoru
analyzer = TrafficAnalyzer([])

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
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# Ana Sayfa (Dashboard)
@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})

# Tarama İstek Modeli
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"

# Nmap Tarama API
@app.post("/api/scan")
async def run_scan(req: ScanRequest):
    # Arka planda asenkron olarak komut çalıştırmak için asyncio kullanılır
    # Hızlıca nmap komutlarını ayarlayalım
    hedef = req.target
    komut_listesi = ["nmap", "-T4", "-F", hedef] if req.scan_type == "quick" else ["nmap", "-sV", "-O", hedef]
    
    # WebSocket ile anlık "Başladı" mesajı atabiliriz
    await manager.broadcast({"type": "info", "message": f"{hedef} için tarama başlatılıyor..."})
    
    # Nmap calistirma
    sonuc_text = nmap_calistir(komut_listesi, hedef, f"web_scan_{hedef}")
    
    if sonuc_text:
        return {"status": "success", "result": sonuc_text, "report_path": f"taramalar/rapor_web_scan_{hedef}.txt"}
    return {"status": "error", "message": "Tarama başarısız oldu."}

# Canlı Sistem Metrikleri & Log Akışı (WebSocket)
@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Burası canlı pcap okuma veya logları tarayıcıya basmak için eklenebilir.
            # Şimdilik heartbeat olarak bırakalım
            await asyncio.sleep(2)
            await websocket.send_json({"type": "ping", "message": "Alive"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
