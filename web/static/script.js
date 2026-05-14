document.addEventListener('DOMContentLoaded', () => {
    
    const terminalOutput = document.getElementById('terminal-output');
    const scanForm = document.getElementById('scan-form');
    const scanLoader = document.getElementById('scan-loader');
    const clearBtn = document.getElementById('clear-btn');
    const btnScan = document.getElementById('btn-scan');
    const pcapForm = document.getElementById('pcap-form');
    const btnPcap = document.getElementById('btn-pcap');
    const pcapFile = document.getElementById('pcap-file');
    
    // Canlı İzleme Butonları ve Etiketleri
    const btnStartSniff = document.getElementById('btn-start-sniff');
    const btnStopSniff = document.getElementById('btn-stop-sniff');
    const liveStatusBadge = document.getElementById('live-status-badge');
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

    // PCAP Dosyasi Yukleme
    pcapForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = pcapFile.files[0];
        if(!file) return;

        logToTerminal(`📂 '${file.name}' dosyası yükleniyor ve analiz ediliyor... Lütfen bekleyin.`, 'info');
        scanLoader.style.display = 'block';
        btnPcap.disabled = true;
        btnPcap.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> İşleniyor';

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/api/pcap_upload', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if(data.status === 'success') {
                logToTerminal(`✅ PCAP analizi tamamlandı!`, 'success');
                // Gelen sonuclari ekrana dök
                const stats = data.data;
                const resultText = `
[PROTOKOL DAĞILIMI]
DNS: ${stats.protocol_distribution.DNS || 0} paket
HTTP: ${stats.protocol_distribution.HTTP || 0} paket
HTTPS: ${stats.protocol_distribution.HTTPS || 0} paket

[TOP TALKERS]
${stats.top_talkers.map(t => `- ${t.ip}: ${t.count} paket [Konum: ${t.location}]`).join('\n')}

[TESPİT EDİLEN ANOMALİLER]
${stats.anomalies.length > 0 ? stats.anomalies.map(a => `! [${a.type}] IP: ${a.source_ip} - ${a.details}`).join('\n') : 'Anomali tespit edilmedi.'}
                `;
                terminalOutput.innerHTML += `<pre style="color:#e2e8f0; margin-top:10px; border-top:1px dashed #333; padding-top:10px; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; white-space: pre-wrap;">${resultText}</pre>\n`;
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
                
                // Stat widget guncelle
                document.querySelector('.warning .stat-value').innerText = stats.anomalies.filter(a => a.type === 'PORT_SCAN').length;
                document.querySelector('.danger .stat-value').innerText = stats.anomalies.filter(a => a.type.includes('DNS_TUNNELING')).length;
                
            } else {
                logToTerminal(`❌ Analiz hatası: ${data.message}`, 'error');
            }

        } catch (error) {
            logToTerminal(`❌ Bağlantı hatası: ${error.message}`, 'error');
        } finally {
            scanLoader.style.display = 'none';
            btnPcap.disabled = false;
            btnPcap.innerHTML = '<i class="fa-solid fa-upload"></i> Yükle ve Analiz Et';
            pcapForm.reset();
        }
    });

    // Canlı İzleme Başlat
    btnStartSniff.addEventListener('click', async () => {
        try {
            const response = await fetch('/api/sniff/start', { method: 'POST' });
            const data = await response.json();
            
            if(data.status === 'success') {
                btnStartSniff.style.display = 'none';
                btnStopSniff.style.display = 'inline-block';
                liveStatusBadge.innerText = 'Dinleniyor...';
                liveStatusBadge.style.backgroundColor = 'var(--primary-color)';
                liveStatusBadge.style.color = '#000';
            } else {
                logToTerminal(`❌ Canlı izleme başlatılamadı: ${data.message}`, 'error');
            }
        } catch(error) {
            logToTerminal(`❌ Bağlantı hatası: ${error.message}`, 'error');
        }
    });

    // Canlı İzleme Durdur ve Analiz Et
    btnStopSniff.addEventListener('click', async () => {
        btnStopSniff.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analiz Ediliyor';
        btnStopSniff.disabled = true;
        
        try {
            const response = await fetch('/api/sniff/stop', { method: 'POST' });
            const data = await response.json();
            
            if(data.status === 'success') {
                btnStopSniff.style.display = 'none';
                btnStartSniff.style.display = 'inline-block';
                liveStatusBadge.innerText = 'Kapalı';
                liveStatusBadge.style.backgroundColor = 'var(--text-muted)';
                liveStatusBadge.style.color = '#fff';
                
                // Analiz sonuclarini bas
                if(data.data && Object.keys(data.data).length > 0) {
                    const stats = data.data;
                    const resultText = `
[CANLI ANALİZ SONUÇLARI]
Toplam Yakalanan Paket: ${stats.total_packets || 0}
HTTP: ${stats.protocol_distribution.HTTP || 0} | HTTPS: ${stats.protocol_distribution.HTTPS || 0} | DNS: ${stats.protocol_distribution.DNS || 0}

[TESPİT EDİLEN ANOMALİLER]
${stats.anomalies.length > 0 ? stats.anomalies.map(a => `! [${a.type}] IP: ${a.source_ip} - ${a.details}`).join('\n') : 'Anomali tespit edilmedi.'}
                    `;
                    terminalOutput.innerHTML += `<pre style="color:#e2e8f0; margin-top:10px; border-top:1px dashed #333; padding-top:10px; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; white-space: pre-wrap;">${resultText}</pre>\n`;
                    terminalOutput.scrollTop = terminalOutput.scrollHeight;
                }
            } else {
                logToTerminal(`❌ Canlı izleme durdurulamadı: ${data.message}`, 'error');
            }
        } catch(error) {
            logToTerminal(`❌ Bağlantı hatası: ${error.message}`, 'error');
        } finally {
            btnStopSniff.innerHTML = '<i class="fa-solid fa-stop"></i> Dinlemeyi Durdur & Analiz Et';
            btnStopSniff.disabled = false;
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
            } else if (data.type === 'live_traffic') {
                // Ekrana canli paket akisini (matrix gibi) basicaz
                if(data.latest && data.latest.length > 0) {
                    data.latest.forEach(pkt => {
                        const line = `<span style="color:var(--primary-color); font-size: 0.85em;">~ ${pkt}</span>\n`;
                        terminalOutput.innerHTML += line;
                    });
                    terminalOutput.scrollTop = terminalOutput.scrollHeight;
                    liveStatusBadge.innerText = `Dinleniyor (${data.count} paket)`;
                }
            } else if (data.type === 'success') {
                logToTerminal(data.message, 'success');
            }
        };

        ws.onclose = () => {
            logToTerminal('⚠️ Veri akışı koptu. Tekrar bağlanılıyor...', 'error');
            setTimeout(connectWebSocket, 3000);
        };
    }

    connectWebSocket();
});
