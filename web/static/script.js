document.addEventListener('DOMContentLoaded', () => {
    
    const terminalOutput = document.getElementById('terminal-output');
    const scanForm = document.getElementById('scan-form');
    const scanLoader = document.getElementById('scan-loader');
    const clearBtn = document.getElementById('clear-btn');
    const btnScan = document.getElementById('btn-scan');

    // Terminal log yazici
    function logToTerminal(message, type = 'info') {
        const time = new Date().toLocaleTimeString();
        let color = '#00f0ff'; // default info color
        if(type === 'success') color = '#00ff66';
        if(type === 'error') color = '#ff3366';
        if(type === 'warning') color = '#ffcc00';

        const line = `<span style="color:#94a3b8">[${time}]</span> <span style="color:${color}">${message}</span>\n`;
        terminalOutput.innerHTML += line;
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }

    // Ekran temizle
    clearBtn.addEventListener('click', () => {
        terminalOutput.innerHTML = '';
        logToTerminal('Terminal temizlendi.', 'success');
    });

    // Nmap Taramasi Baslat
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const targetIp = document.getElementById('target-ip').value;
        const scanType = document.querySelector('input[name="scan_type"]:checked').value;

        logToTerminal(`🚀 ${targetIp} hedefine Nmap taraması başlatılıyor... Lütfen bekleyin.`, 'info');
        scanLoader.style.display = 'block';
        btnScan.disabled = true;
        btnScan.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Taranıyor';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: targetIp,
                    scan_type: scanType
                })
            });

            const data = await response.json();

            if(data.status === 'success') {
                logToTerminal(`✅ Tarama başarıyla tamamlandı. Rapor yolu: ${data.report_path}`, 'success');
                // Nmap ciktisini ekrana yansit
                terminalOutput.innerHTML += `<div style="color:#e2e8f0; margin-top:10px; border-top:1px dashed #333; padding-top:10px;">${data.result}</div>\n`;
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
            } else {
                logToTerminal(`❌ Tarama başarısız: ${data.message}`, 'error');
            }

        } catch (error) {
            logToTerminal(`❌ Bağlantı hatası: ${error.message}`, 'error');
        } finally {
            scanLoader.style.display = 'none';
            btnScan.disabled = false;
            btnScan.innerHTML = '<i class="fa-solid fa-play"></i> Başlat';
        }
    });

    // WebSocket Baglantisi (Canli metrikler)
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/traffic`;
        
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            logToTerminal('📡 Gerçek zamanlı veri akışına bağlanıldı.', 'success');
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'info') {
                logToTerminal(data.message, 'warning');
            }
            // Ilerde canlı paket sayısı, anomali uyarilari burdan basilabilir
        };

        ws.onclose = () => {
            logToTerminal('⚠️ Veri akışı koptu. Tekrar bağlanılıyor...', 'error');
            setTimeout(connectWebSocket, 3000);
        };
    }

    connectWebSocket();
});
