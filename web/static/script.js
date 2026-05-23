document.addEventListener('DOMContentLoaded', () => {

    // ═══════════════════════════════════════════════
    // MENÜ GEÇİŞ MANTIĞI
    // ═══════════════════════════════════════════════
    const navItems = document.querySelectorAll('.nav-menu li');
    const sections = document.querySelectorAll('.section-page');
    const pageTitle = document.getElementById('page-title');

    const pageTitles = {
        dashboard: 'Siber Güvenlik Komuta Merkezi',
        live:      'Canlı Ağ İzleme',
        nmap:      'Nmap Hedef Taraması',
        pcap:      'PCAP Trafik Analizi',
        settings:  'Ayarlar',
        guide:     'Görsel Rehber & Eğitim',
    };

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.getAttribute('data-section');

            // Aktif menü
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            // Aktif section
            sections.forEach(s => s.classList.remove('active'));
            const targetSection = document.getElementById(`section-${target}`);
            if (targetSection) targetSection.classList.add('active');

            // Başlık güncelle
            if (pageTitles[target]) pageTitle.textContent = pageTitles[target];
        });
    });

    // ═══════════════════════════════════════════════
    // YARDIMCI FONKSİYONLAR
    // ═══════════════════════════════════════════════
    function logTo(el, message, type = 'info') {
        const time = new Date().toLocaleTimeString();
        let color = '#00f0ff';
        if (type === 'success') color = '#00ff66';
        if (type === 'error')   color = '#ff3366';
        if (type === 'warning') color = '#ffcc00';
        el.innerHTML += `<span style="color:#94a3b8">[${time}]</span> <span style="color:${color}">${message}</span>\n`;
        el.scrollTop = el.scrollHeight;
    }

    // ═══════════════════════════════════════════════
    // DASHBOARD — Terminal Temizle
    // ═══════════════════════════════════════════════
    const terminalOutput = document.getElementById('terminal-output');
    const clearBtn = document.getElementById('clear-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            terminalOutput.innerHTML = '';
            logTo(terminalOutput, 'Terminal temizlendi.', 'success');
        });
    }

    // ═══════════════════════════════════════════════
    // NMAP TARAMASI
    // ═══════════════════════════════════════════════
    const nmapOutput  = document.getElementById('nmap-output');
    const scanForm    = document.getElementById('scan-form');
    const nmapLoader  = document.getElementById('nmap-loader');
    const btnScan     = document.getElementById('btn-scan');
    const clearNmapBtn = document.getElementById('clear-nmap-btn');

    if (clearNmapBtn) {
        clearNmapBtn.addEventListener('click', () => {
            nmapOutput.innerHTML = '';
            logTo(nmapOutput, 'Terminal temizlendi.', 'success');
        });
    }

    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const targetIp = document.getElementById('target-ip').value;
            const scanType = document.querySelector('input[name="scan_type"]:checked').value;

            logTo(nmapOutput, `🚀 ${targetIp} hedefine Nmap taraması başlatılıyor... Lütfen bekleyin.`, 'info');
            logTo(terminalOutput, `🚀 Nmap taraması başlatıldı → ${targetIp}`, 'warning');
            nmapLoader.style.display = 'block';
            btnScan.disabled = true;
            btnScan.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Taranıyor';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: targetIp, scan_type: scanType })
                });
                const data = await response.json();

                if (data.status === 'success') {
                    logTo(nmapOutput, `✅ Tarama tamamlandı. Rapor: ${data.report_path}`, 'success');
                    logTo(terminalOutput, `✅ Nmap taraması tamamlandı → ${targetIp}`, 'success');
                    nmapOutput.innerHTML += `<div style="color:#e2e8f0; margin-top:10px; border-top:1px dashed #333; padding-top:10px;">${data.result}</div>\n`;
                    nmapOutput.scrollTop = nmapOutput.scrollHeight;
                } else {
                    logTo(nmapOutput, `❌ Tarama başarısız: ${data.message}`, 'error');
                }
            } catch (error) {
                logTo(nmapOutput, `❌ Bağlantı hatası: ${error.message}`, 'error');
            } finally {
                nmapLoader.style.display = 'none';
                btnScan.disabled = false;
                btnScan.innerHTML = '<i class="fa-solid fa-play"></i> Başlat';
            }
        });
    }

    // ═══════════════════════════════════════════════
    // PCAP ANALİZİ
    // ═══════════════════════════════════════════════
    const pcapOutput  = document.getElementById('pcap-output');
    const pcapForm    = document.getElementById('pcap-form');
    const pcapLoader  = document.getElementById('pcap-loader');
    const btnPcap     = document.getElementById('btn-pcap');
    const pcapFile    = document.getElementById('pcap-file');
    const clearPcapBtn = document.getElementById('clear-pcap-btn');

    if (clearPcapBtn) {
        clearPcapBtn.addEventListener('click', () => {
            pcapOutput.innerHTML = '';
            logTo(pcapOutput, 'Terminal temizlendi.', 'success');
        });
    }

    if (pcapForm) {
        pcapForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const file = pcapFile.files[0];
            if (!file) return;

            logTo(pcapOutput, `📂 '${file.name}' yükleniyor ve analiz ediliyor...`, 'info');
            logTo(terminalOutput, `📂 PCAP analizi başlatıldı → ${file.name}`, 'warning');
            pcapLoader.style.display = 'block';
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

                if (data.status === 'success') {
                    logTo(pcapOutput, `✅ PCAP analizi tamamlandı!`, 'success');
                    logTo(terminalOutput, `✅ PCAP analizi tamamlandı → ${file.name}`, 'success');
                    const stats = data.data;
                    const resultText = `
[PROTOKOL DAĞILIMI]
DNS:   ${stats.protocol_distribution?.DNS   || 0} paket
HTTP:  ${stats.protocol_distribution?.HTTP  || 0} paket
HTTPS: ${stats.protocol_distribution?.HTTPS || 0} paket

[TOP TALKERS]
${stats.top_talkers?.map(t => `- ${t.ip}: ${t.count} paket [${t.location}]`).join('\n') || 'Veri yok'}

[TESPİT EDİLEN ANOMALİLER]
${stats.anomalies?.length > 0
    ? stats.anomalies.map(a => `! [${a.type}] IP: ${a.source_ip} - ${a.details}`).join('\n')
    : 'Anomali tespit edilmedi.'}
                    `;
                    pcapOutput.innerHTML += `<pre style="color:#e2e8f0; margin-top:10px; border-top:1px dashed #333; padding-top:10px; font-family:'JetBrains Mono',monospace; font-size:0.9em; white-space:pre-wrap;">${resultText}</pre>\n`;
                    pcapOutput.scrollTop = pcapOutput.scrollHeight;

                    // Dashboard stat güncelle
                    const statPort = document.getElementById('stat-port-scan');
                    const statDns  = document.getElementById('stat-dns-tunnel');
                    const statTotal = document.getElementById('stat-total-packets');
                    if (statPort) statPort.innerText = stats.anomalies?.filter(a => a.type === 'PORT_SCAN').length || 0;
                    if (statDns)  statDns.innerText  = stats.anomalies?.filter(a => a.type?.includes('DNS_TUNNELING')).length || 0;
                    if (statTotal) statTotal.innerText = stats.total_packets || 0;
                } else {
                    logTo(pcapOutput, `❌ Analiz hatası: ${data.message}`, 'error');
                }
            } catch (error) {
                logTo(pcapOutput, `❌ Bağlantı hatası: ${error.message}`, 'error');
            } finally {
                pcapLoader.style.display = 'none';
                btnPcap.disabled = false;
                btnPcap.innerHTML = '<i class="fa-solid fa-upload"></i> Yükle ve Analiz Et';
                pcapForm.reset();
            }
        });
    }

    // ═══════════════════════════════════════════════
    // CANLI İZLEME
    // ═══════════════════════════════════════════════
    const liveOutput      = document.getElementById('live-output');
    const btnStartSniff   = document.getElementById('btn-start-sniff');
    const btnStopSniff    = document.getElementById('btn-stop-sniff');
    const liveStatusBadge = document.getElementById('live-status-badge');

    if (btnStartSniff) {
        btnStartSniff.addEventListener('click', async () => {
            try {
                const response = await fetch('/api/sniff/start', { method: 'POST' });
                const data = await response.json();
                if (data.status === 'success') {
                    btnStartSniff.style.display = 'none';
                    btnStopSniff.style.display = 'inline-block';
                    liveStatusBadge.innerText = 'Dinleniyor...';
                    liveStatusBadge.style.backgroundColor = 'var(--primary-color)';
                    liveStatusBadge.style.color = '#000';
                    logTo(liveOutput, '📡 Canlı dinleme başlatıldı.', 'success');
                    logTo(terminalOutput, '📡 Canlı dinleme başlatıldı.', 'success');
                } else {
                    logTo(liveOutput, `❌ Başlatılamadı: ${data.message}`, 'error');
                }
            } catch (error) {
                logTo(liveOutput, `❌ Bağlantı hatası: ${error.message}`, 'error');
            }
        });
    }

    if (btnStopSniff) {
        btnStopSniff.addEventListener('click', async () => {
            btnStopSniff.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analiz Ediliyor';
            btnStopSniff.disabled = true;
            try {
                const response = await fetch('/api/sniff/stop', { method: 'POST' });
                const data = await response.json();
                if (data.status === 'success') {
                    btnStopSniff.style.display = 'none';
                    btnStartSniff.style.display = 'inline-block';
                    liveStatusBadge.innerText = 'Kapalı';
                    liveStatusBadge.style.backgroundColor = 'var(--text-muted)';
                    liveStatusBadge.style.color = '#fff';

                    if (data.data && Object.keys(data.data).length > 0) {
                        const stats = data.data;
                        const resultText = `
[CANLI ANALİZ SONUÇLARI]
Toplam Yakalanan Paket: ${stats.total_packets || 0}
HTTP: ${stats.protocol_distribution?.HTTP || 0} | HTTPS: ${stats.protocol_distribution?.HTTPS || 0} | DNS: ${stats.protocol_distribution?.DNS || 0}

[TESPİT EDİLEN ANOMALİLER]
${stats.anomalies?.length > 0
    ? stats.anomalies.map(a => `! [${a.type}] IP: ${a.source_ip} - ${a.details}`).join('\n')
    : 'Anomali tespit edilmedi.'}
                        `;
                        liveOutput.innerHTML += `<pre style="color:#e2e8f0; margin-top:10px; border-top:1px dashed #333; padding-top:10px; font-family:'JetBrains Mono',monospace; font-size:0.9em; white-space:pre-wrap;">${resultText}</pre>\n`;
                        liveOutput.scrollTop = liveOutput.scrollHeight;

                        const statTotal = document.getElementById('stat-total-packets');
                        if (statTotal) statTotal.innerText = stats.total_packets || 0;
                    } else {
                        logTo(liveOutput, data.message || 'Dinleme durduruldu.', 'warning');
                    }
                    logTo(terminalOutput, '🛑 Canlı dinleme durduruldu.', 'warning');
                } else {
                    logTo(liveOutput, `❌ Durdurulamadı: ${data.message}`, 'error');
                }
            } catch (error) {
                logTo(liveOutput, `❌ Bağlantı hatası: ${error.message}`, 'error');
            } finally {
                btnStopSniff.innerHTML = '<i class="fa-solid fa-stop"></i> Dinlemeyi Durdur & Analiz Et';
                btnStopSniff.disabled = false;
            }
        });
    }

    // ═══════════════════════════════════════════════
    // WEBSOCKET — Canlı veri akışı
    // ═══════════════════════════════════════════════
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/traffic`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            logTo(terminalOutput, '📡 Gerçek zamanlı veri akışına bağlanıldı.', 'success');
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'info') {
                logTo(terminalOutput, data.message, 'warning');
            } else if (data.type === 'live_traffic') {
                if (data.latest && data.latest.length > 0 && liveOutput) {
                    data.latest.forEach(pkt => {
                        liveOutput.innerHTML += `<span style="color:var(--primary-color); font-size:0.85em;">~ ${pkt}</span>\n`;
                    });
                    liveOutput.scrollTop = liveOutput.scrollHeight;
                    if (liveStatusBadge) liveStatusBadge.innerText = `Dinleniyor (${data.count} paket)`;
                }
            } else if (data.type === 'success') {
                logTo(terminalOutput, data.message, 'success');
            }
        };

        ws.onclose = () => {
            logTo(terminalOutput, '⚠️ Veri akışı koptu. Tekrar bağlanılıyor...', 'error');
            setTimeout(connectWebSocket, 3000);
        };
    }

    // ═══════════════════════════════════════════════
    // GÖRSEL REHBER TABS & ACCORDION
    // ═══════════════════════════════════════════════
    const guideTabs = document.querySelectorAll('.guide-tabs .btn-tab');
    const guideContents = document.querySelectorAll('.guide-tab-content');

    guideTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabTarget = tab.getAttribute('data-guide-tab');

            // Tab butonlarını güncelle
            guideTabs.forEach(t => {
                t.classList.remove('active');
                t.style.color = 'var(--text-muted)';
            });
            tab.classList.add('active');
            tab.style.color = '#000';

            // Tab içeriklerini güncelle
            guideContents.forEach(content => {
                content.style.display = 'none';
                content.classList.remove('active-tab');
            });

            const activeContent = document.getElementById(`guide-tab-${tabTarget}`);
            if (activeContent) {
                activeContent.style.display = tabTarget === 'infographic' ? 'grid' : 'block';
                activeContent.classList.add('active-tab');
            }
        });
    });

    const accordionHeaders = document.querySelectorAll('.acc-header');
    accordionHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const group = header.parentElement;
            const body = group.querySelector('.acc-body');
            const isOpened = group.classList.contains('active-group');

            // Tüm accordiyonları kapat (Opsiyonel: Akordeon davranışı)
            document.querySelectorAll('.acc-group').forEach(g => {
                g.classList.remove('active-group');
                g.querySelector('.acc-body').style.display = 'none';
            });

            if (!isOpened) {
                group.classList.add('active-group');
                body.style.display = 'flex';
            }
        });
    });

    connectWebSocket();
});
