// --- Dark Mode Chart Defaults ---
Chart.defaults.color = '#aaa';
Chart.defaults.borderColor = '#333';

// --- Traffic Line Chart ---
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Packets/Sec',
            data: [],
            borderColor: '#00d4ff',
            backgroundColor: 'rgba(0, 212, 255, 0.1)',
            borderWidth: 2,
            tension: 0.4,
            fill: true,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { grid: { display: false } },
            y: { beginAtZero: true, grid: { color: '#222' } }
        }
    }
});

// --- Protocol Doughnut Chart ---
const protoCtx = document.getElementById('protoChart').getContext('2d');
const protoChart = new Chart(protoCtx, {
    type: 'doughnut',
    data: {
        labels: ['TCP', 'UDP', 'ICMP'],
        datasets: [{
            data: [1, 1, 1],
            backgroundColor: ['#00ff88', '#ff9f43', '#ff4d4d'],
            borderWidth: 0
        }]
    },
    options: {
        cutout: '75%',
        plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } }
    }
});

// --- WebSocket & Logic ---
let stompClient = null;
let ipCache = {}; // Cache country codes to avoid API spam

function connect() {
    const socket = new SockJS('/ws-sentinel');
    stompClient = Stomp.over(socket);
    stompClient.debug = null;

    stompClient.connect({}, function (frame) {
        document.getElementById('connStatus').innerHTML = '<i class="fas fa-circle"></i> Online';

        stompClient.subscribe('/topic/stats', function (data) {
            updateDashboard(JSON.parse(data.body));
        });

        stompClient.subscribe('/topic/alerts', function (data) {
            showAlert(JSON.parse(data.body));
        });

        fetchHistory();
    });
}

function updateDashboard(stats) {
    document.getElementById('ppsValue').innerText = stats.pps;
    document.getElementById('bwValue').innerText = formatBytes(stats.bandwidth); // This is total bandwidth
    document.getElementById('flowValue').innerText = stats.activeFlows;

    // Update Chart
    const now = new Date().toLocaleTimeString();
    if (trafficChart.data.labels.length > 20) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
    }
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(stats.pps);
    trafficChart.update();

    // Update Pie
    protoChart.data.datasets[0].data = [stats.tcp, stats.udp, stats.icmp];
    protoChart.update();
}

function showAlert(alert) {
    const container = document.getElementById('alertContainer');
    if(container.innerText.includes("System Secure")) container.innerHTML = "";

    const div = document.createElement('div');
    div.className = `alert-item alert-${alert.severity}`;
    div.innerHTML = `
        <div class="d-flex justify-content-between">
            <strong>${alert.type}</strong>
            <small>${new Date(alert.timestamp).toLocaleTimeString()}</small>
        </div>
        <div class="small">${alert.description}</div>
    `;

    container.insertBefore(div, container.firstChild);

    // Visual Alarm
    const threatLabel = document.getElementById('statusValue');
    if(alert.severity === 'CRITICAL') {
        threatLabel.innerText = "CRITICAL THREAT";
        threatLabel.className = "metric-value text-neon-red";
        // Flash effect
        document.body.style.boxShadow = "inset 0 0 50px rgba(255,0,0,0.2)";
        setTimeout(() => {
             threatLabel.innerText = "SECURE";
             threatLabel.className = "metric-value text-neon-green";
             document.body.style.boxShadow = "none";
        }, 5000);
    }
}

function fetchFlows() {
    fetch('/api/flows').then(r => r.json()).then(flows => {
        const tbody = document.getElementById('flowTableBody');
        tbody.innerHTML = '';

        // Sort by packet count desc
        flows.sort((a, b) => b.packetCount - a.packetCount);

        flows.slice(0, 6).forEach(flow => {
            // Resolve Country (Async)
            let country = ipCache[flow.srcIp] || '...';
            if (!ipCache[flow.srcIp] && !isPrivateIp(flow.srcIp)) {
                fetch(`http://ip-api.com/json/${flow.srcIp}?fields=countryCode`)
                    .then(r => r.json())
                    .then(data => {
                        ipCache[flow.srcIp] = data.countryCode || 'UNK';
                    });
            } else if (isPrivateIp(flow.srcIp)) {
                 ipCache[flow.srcIp] = 'LAN';
            }

            // ADDED: Bytes column display using formatBytes()
            // Note: flow.bytes is total bytes transferred in this flow
            // If you want bits, multiply by 8. formatBytes handles B/KB/MB.
            let formattedBytes = formatBytes(flow.bytes * 8);

            tbody.innerHTML += `
                <tr>
                    <td class="text-neon-blue">${flow.srcIp}</td>
                    <td><span class="badge bg-secondary">${ipCache[flow.srcIp] || 'LAN'}</span></td>
                    <td>${flow.dstIp}</td>
                    <td>${flow.protocol}</td>
                    <td>${formattedBytes}</td>
                    <td><button class="btn btn-danger btn-block-ip" onclick="blockIp('${flow.srcIp}')"><i class="fas fa-ban"></i></button></td>
                </tr>`;
        });
    });
}

function isPrivateIp(ip) {
    return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("172.");
}

// --- Blocking Actions ---
function blockIp(ip) {
    if(!confirm(`Block traffic from ${ip}?`)) return;
    fetch(`/api/block/${ip}`, { method: 'POST' })
        .then(r => {
            if(r.ok) {
                alert(`${ip} has been added to the blacklist.`);
                loadBlockedIps();
            }
        });
}

function unblockIp(ip) {
    fetch(`/api/unblock/${ip}`, { method: 'POST' })
        .then(r => { if(r.ok) loadBlockedIps(); });
}

function loadBlockedIps() {
    fetch('/api/blocked').then(r => r.json()).then(ips => {
        const tbody = document.getElementById('blockedTableBody');
        tbody.innerHTML = '';
        ips.forEach(ip => {
            tbody.innerHTML += `
                <tr>
                    <td class="text-neon-red">${ip}</td>
                    <td><button class="btn btn-success btn-sm" onclick="unblockIp('${ip}')">Unblock</button></td>
                </tr>`;
        });
    });
}

// --- Utility ---
// Adjusted to handle bits (b) vs Bytes (B) contextually if needed
// Currently assumes input is bits/sec for bandwidth, but flows usually track Bytes.
// The code in updateDashboard passes bits/sec. The code in fetchFlows passes bits (Bytes*8).
function formatBytes(bits) {
    if(bits === 0) return '0 b';
    const k = 1024;
    const i = Math.floor(Math.log(bits) / Math.log(k));
    // Use 'b' for bits, 'Kb' for Kilobits etc. or 'B' if you prefer Bytes.
    // Standard network convention is often bits/sec.
    const sizes = ['b', 'Kb', 'Mb', 'Gb', 'Tb'];
    return parseFloat((bits / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function clearAlerts() {
    document.getElementById('alertContainer').innerHTML = '<div class="text-muted text-center mt-5 opacity-50"><i class="fas fa-check-circle fa-3x mb-3"></i><br>System Secure</div>';
}

// --- Navigation ---
function showSection(sectionId) {
    document.querySelectorAll('.main-content > div').forEach(div => div.classList.add('d-none'));
    document.getElementById(sectionId + 'Section').classList.remove('d-none');

    document.querySelectorAll('.nav-link').forEach(a => a.classList.remove('active'));
    document.getElementById('nav-' + sectionId).classList.add('active');

    if(sectionId === 'forensics') loadForensics();
    if(sectionId === 'settings') loadSettings();
    if(sectionId === 'blocked') loadBlockedIps();
}

function loadForensics() {
    fetch('/api/forensics').then(r => r.json()).then(files => {
        const tbody = document.getElementById('forensicsTableBody');
        tbody.innerHTML = '';
        files.forEach(file => {
            tbody.innerHTML += `<tr><td>${file}</td><td>PCAP</td><td><a href="/api/forensics/download/${file}" class="btn btn-sm btn-outline-primary">Download</a></td></tr>`;
        });
    });
}
function loadSettings() {
    fetch('/api/settings').then(r => r.json()).then(settings => {
        document.getElementById('synThreshold').value = settings.synFloodThreshold;
        document.getElementById('scanThreshold').value = settings.portScanThreshold;
        document.getElementById('zThreshold').value = settings.zScoreThreshold;
    });
}
function saveSettings(event) {
    event.preventDefault();
    const settings = {
        synFloodThreshold: document.getElementById('synThreshold').value,
        portScanThreshold: document.getElementById('scanThreshold').value,
        zScoreThreshold: document.getElementById('zThreshold').value
    };
    fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) })
        .then(r => alert(r.ok ? "Saved" : "Error"));
}

function fetchHistory() {
    fetch('/api/alerts/history').then(r => r.json()).then(alerts => alerts.forEach(a => showAlert(a)));
}

connect();
setInterval(fetchFlows, 2000);