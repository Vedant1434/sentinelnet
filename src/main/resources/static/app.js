// --- Dark Mode Chart Defaults ---
Chart.defaults.color = '#aaa';
Chart.defaults.borderColor = '#333';

// Helper to safely get context
function getChartCtx(id) {
    const el = document.getElementById(id);
    if (el) {
        return el.getContext('2d');
    }
    console.warn(`Chart element MISSING: ${id} - Check dashboard.html`);
    return null;
}

// --- Traffic Line Chart ---
let trafficChart;
const trafficCtx = getChartCtx('trafficChart');
if (trafficCtx) {
    trafficChart = new Chart(trafficCtx, {
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
}

// --- Protocol Doughnut Chart ---
let protoChart;
const protoCtx = getChartCtx('protoChart');
if (protoCtx) {
    protoChart = new Chart(protoCtx, {
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
}

// --- Top Ports Bar Chart ---
let portChart;
const portCtx = getChartCtx('portChart');
if (portCtx) {
    portChart = new Chart(portCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets',
                data: [],
                backgroundColor: '#e94560',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: '#222' } },
                x: { grid: { display: false } }
            }
        }
    });
}

// --- Alert Timeline Chart ---
let alertChart;
const alertCtx = getChartCtx('alertChart');
if (alertCtx) {
    alertChart = new Chart(alertCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                borderColor: '#ff9f43',
                backgroundColor: 'rgba(255, 159, 67, 0.1)',
                borderWidth: 2,
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: '#222' } },
                x: { grid: { display: false } }
            }
        }
    });
}

// --- WebSocket & Logic ---
let stompClient = null;
let ipCache = {};
let alertCountBuffer = 0;

function connect() {
    const socket = new SockJS('/ws-sentinel');
    stompClient = Stomp.over(socket);
    stompClient.debug = null;

    stompClient.connect({}, function (frame) {
        console.log("WebSocket Connected");
        // Status will be set to ONLINE/PAUSED when first stats arrive.

        stompClient.subscribe('/topic/stats', function (data) {
            updateDashboard(JSON.parse(data.body));
        });

        stompClient.subscribe('/topic/alerts', function (data) {
            const alert = JSON.parse(data.body);
            showAlert(alert);
            alertCountBuffer++;
        });

        stompClient.subscribe('/topic/flows', function (data) {
            updateFlowTable(JSON.parse(data.body));
        });

        fetchHistory();
        fetch('/api/flows').then(r => r.json()).then(flows => updateFlowTable(flows));
        checkCaptureStatus();
    }, function(error) {
        // ERROR CALLBACK: Handles Offline State
        console.error("WebSocket Error/Disconnect:", error);
        updateSystemStatus("OFFLINE");
        // Try to reconnect after 5 seconds
        setTimeout(connect, 5000);
    });
}

// --- NEW: Update System Status UI ---
function updateSystemStatus(state) {
    const el = document.getElementById('connStatus');
    if (!el) return;

    switch (state) {
        case 'ONLINE':
            el.innerHTML = '<i class="fas fa-circle"></i> Online';
            el.className = 'text-neon-green'; // Defined in CSS
            break;
        case 'PAUSED':
            el.innerHTML = '<i class="fas fa-pause-circle"></i> Paused';
            el.className = 'text-warning'; // Bootstrap yellow
            break;
        case 'OFFLINE':
            el.innerHTML = '<i class="fas fa-times-circle"></i> Offline';
            el.className = 'text-danger'; // Bootstrap red
            break;
    }
}

function updateDashboard(stats) {
    if(document.getElementById('ppsValue')) document.getElementById('ppsValue').innerText = stats.pps;
    if(document.getElementById('bwValue')) document.getElementById('bwValue').innerText = formatBytes(stats.bandwidth);
    if(document.getElementById('flowValue')) document.getElementById('flowValue').innerText = stats.activeFlows;

    // UPDATE STATUS UI based on backend capturing state
    if (stats.capturing) {
        updateSystemStatus('ONLINE');
    } else {
        updateSystemStatus('PAUSED');
    }

    // Sync UI buttons as well
    updateCaptureUI(stats.capturing);

    const now = new Date().toLocaleTimeString();

    // 1. Update Traffic Chart
    if (trafficChart) {
        if (trafficChart.data.labels.length > 20) {
            trafficChart.data.labels.shift();
            trafficChart.data.datasets[0].data.shift();
        }
        trafficChart.data.labels.push(now);
        trafficChart.data.datasets[0].data.push(stats.pps);
        trafficChart.update();
    }

    // 2. Update Protocol Chart
    if (protoChart) {
        protoChart.data.datasets[0].data = [stats.tcp, stats.udp, stats.icmp];
        protoChart.update();
    }

    // 3. Update Port Chart
    if (portChart) {
        if (stats.topPorts && Object.keys(stats.topPorts).length > 0) {
            portChart.data.labels = Object.keys(stats.topPorts);
            portChart.data.datasets[0].data = Object.values(stats.topPorts);
        }
        portChart.update();
    }

    // 4. Update Alert Chart
    if (alertChart) {
        if (alertChart.data.labels.length > 20) {
            alertChart.data.labels.shift();
            alertChart.data.datasets[0].data.shift();
        }
        alertChart.data.labels.push(now);
        alertChart.data.datasets[0].data.push(alertCountBuffer);
        alertChart.update();
        alertCountBuffer = 0; // Reset bucket
    }
}

function showAlert(alert) {
    const container = document.getElementById('alertContainer');
    if (!container) return;

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

    const threatLabel = document.getElementById('statusValue');
    if(threatLabel && alert.severity === 'CRITICAL') {
        threatLabel.innerText = "CRITICAL THREAT";
        threatLabel.className = "metric-value text-neon-red";
        document.body.style.boxShadow = "inset 0 0 50px rgba(255,0,0,0.2)";
        setTimeout(() => {
             threatLabel.innerText = "SECURE";
             threatLabel.className = "metric-value text-neon-green";
             document.body.style.boxShadow = "none";
        }, 5000);
    }
}

function updateFlowTable(flows) {
    const tbody = document.getElementById('flowTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    flows.forEach(flow => {
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

        let formattedBytes = formatBytes(flow.bytes * 8);

        // Display DPI Metadata
        let displayProto = flow.metadata ? `<span class="text-neon-green">${flow.metadata}</span>` : flow.protocol;

        tbody.innerHTML += `
            <tr>
                <td class="text-neon-blue">${flow.srcIp}</td>
                <td><span class="badge bg-secondary">${ipCache[flow.srcIp] || 'LAN'}</span></td>
                <td>${flow.dstIp}</td>
                <td>${displayProto}</td>
                <td>${formattedBytes}</td>
                <td><button class="btn btn-danger btn-block-ip" onclick="blockIp('${flow.srcIp}')"><i class="fas fa-ban"></i></button></td>
            </tr>`;
    });
}

function isPrivateIp(ip) {
    return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("172.");
}

// --- CAPTURE CONTROLS ---
function startCapture() {
    fetch('/api/capture/start', { method: 'POST' })
        .then(r => {
            if(r.ok) {
                // Optimistic UI Update
                updateCaptureUI(true);
                updateSystemStatus("ONLINE");
            }
            else alert("Failed to start capture");
        });
}

function stopCapture() {
    fetch('/api/capture/stop', { method: 'POST' })
        .then(r => {
            if(r.ok) {
                // Optimistic UI Update
                updateCaptureUI(false);
                updateSystemStatus("PAUSED");
            }
            else alert("Failed to stop capture");
        });
}

// --- FILTER LOGIC ---
function applyFilter() {
    const filterInput = document.getElementById('bpfFilterInput');
    const filter = filterInput.value.trim();

    if (!filter) {
        showToast("Warning", "Filter cannot be empty");
        return;
    }

    fetch('/api/capture/filter', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ filter: filter })
    }).then(r => {
        if(r.ok) showToast("Success", `Filter Applied: ${filter}`);
        else showToast("Error", "Invalid Filter Syntax");
    });
}

function clearFilter() {
    document.getElementById('bpfFilterInput').value = '';

    fetch('/api/capture/filter', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ filter: "" })
    }).then(r => {
        if(r.ok) showToast("Info", "Filter Cleared - Capturing All Traffic");
    });
}

function showToast(title, message) {
    const container = document.getElementById('toastContainer');
    const id = 'toast-' + Date.now();
    const html = `
        <div id="${id}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <strong class="me-auto">${title}</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">${message}</div>
        </div>
    `;
    container.insertAdjacentHTML('beforeend', html);
    const toastEl = document.getElementById(id);
    const toast = new bootstrap.Toast(toastEl);
    toast.show();

    toastEl.addEventListener('hidden.bs.toast', () => {
        toastEl.remove();
    });
}

function checkCaptureStatus() {
    fetch('/api/capture/status').then(r => r.json()).then(status => {
        updateCaptureUI(status.running);
        updateSystemStatus(status.running ? "ONLINE" : "PAUSED"); // Sync initial status
        document.getElementById('bpfFilterInput').value = status.filter || '';
    }).catch(e => updateSystemStatus("OFFLINE"));
}

function updateCaptureUI(isRunning) {
    const badge = document.getElementById('captureStatusBadge');
    const startBtn = document.getElementById('btnStart');
    const stopBtn = document.getElementById('btnStop');

    if (isRunning) {
        badge.innerText = "RUNNING";
        badge.className = "badge bg-success";
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        badge.innerText = "STOPPED";
        badge.className = "badge bg-danger";
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
}

// --- BLOCKING ---
function blockIp(ip) {
    Swal.fire({
        title: 'Block IP Address?',
        text: `Traffic from ${ip} will be dropped immediately.`,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#e94560',
        cancelButtonColor: '#3085d6',
        confirmButtonText: 'Yes, Block it!',
        background: '#16213e',
        color: '#ffffff'
    }).then((result) => {
        if (result.isConfirmed) {
            fetch(`/api/block/${ip}`, { method: 'POST' })
                .then(r => {
                    if(r.ok) {
                        loadBlockedIps();
                        Swal.fire({
                            title: 'Blocked!',
                            text: `${ip} has been blacklisted.`,
                            icon: 'success',
                            background: '#16213e',
                            color: '#ffffff',
                            timer: 1500,
                            showConfirmButton: false
                        });
                    }
                });
        }
    });
}

function unblockIp(ip) {
    fetch(`/api/unblock/${ip}`, { method: 'POST' })
        .then(r => { if(r.ok) loadBlockedIps(); });
}

function loadBlockedIps() {
    const tbody = document.getElementById('blockedTableBody');
    if (!tbody) return;
    fetch('/api/blocked').then(r => r.json()).then(ips => {
        tbody.innerHTML = '';
        ips.forEach(ip => {
            tbody.innerHTML += `<tr><td class="text-neon-red">${ip}</td><td><button class="btn btn-success btn-sm" onclick="unblockIp('${ip}')">Unblock</button></td></tr>`;
        });
    });
}

function formatBytes(bits) {
    if(bits === 0) return '0 b';
    const k = 1024;
    const i = Math.floor(Math.log(bits) / Math.log(k));
    const sizes = ['b', 'Kb', 'Mb', 'Gb', 'Tb'];
    return parseFloat((bits / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// --- MODIFIED: Beautiful Alert Clearing ---
function clearAlerts() {
    Swal.fire({
        title: 'Clear Alert History?',
        text: "All security alerts will be permanently deleted from the database.",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#d33',
        cancelButtonColor: '#3085d6',
        confirmButtonText: 'Yes, delete history!',
        background: '#16213e', // Dark theme background
        color: '#e0e0e0'       // Light text
    }).then((result) => {
        if (result.isConfirmed) {
            fetch('/api/alerts/clear', { method: 'DELETE' })
                .then(r => {
                    if (r.ok) {
                        const container = document.getElementById('alertContainer');
                        if (container) {
                            container.innerHTML = '<div class="text-muted text-center mt-5 opacity-50"><i class="fas fa-check-circle fa-3x mb-3"></i><br>System Secure</div>';
                        }
                        Swal.fire({
                            title: 'Deleted!',
                            text: 'Alert history has been wiped.',
                            icon: 'success',
                            background: '#16213e',
                            color: '#ffffff',
                            timer: 1500,
                            showConfirmButton: false
                        });
                    } else {
                        showToast("Error", "Failed to clear alerts.");
                    }
                });
        }
    });
}

function showSection(sectionId) {
    document.querySelectorAll('.main-content > div').forEach(div => div.classList.add('d-none'));
    const section = document.getElementById(sectionId + 'Section');
    if (section) section.classList.remove('d-none');

    document.querySelectorAll('.nav-link').forEach(a => a.classList.remove('active'));
    const nav = document.getElementById('nav-' + sectionId);
    if (nav) nav.classList.add('active');

    if(sectionId === 'forensics') loadForensics();
    if(sectionId === 'settings') loadSettings();
    if(sectionId === 'blocked') loadBlockedIps();
}

function loadForensics() {
    const tbody = document.getElementById('forensicsTableBody');
    if (!tbody) return;

    fetch('/api/forensics').then(r => r.json()).then(files => {
        tbody.innerHTML = '';
        files.forEach(file => {
            tbody.innerHTML += `<tr><td>${file}</td><td>PCAP</td><td><a href="/api/forensics/download/${file}" class="btn btn-sm btn-outline-primary">Download</a></td></tr>`;
        });
    });
}
function loadSettings() {
    fetch('/api/settings').then(r => r.json()).then(settings => {
        if(document.getElementById('synThreshold')) document.getElementById('synThreshold').value = settings.synFloodThreshold;
        if(document.getElementById('scanThreshold')) document.getElementById('scanThreshold').value = settings.portScanThreshold;
        if(document.getElementById('zThreshold')) document.getElementById('zThreshold').value = settings.zScoreThreshold;
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
        .then(r => showToast("Success", "Settings Saved"));
}

function exportAlerts() {
    window.location.href = '/api/alerts/export/csv';
}

function exportFlows() {
    window.location.href = '/api/flows/export/json';
}

function fetchHistory() {
    fetch('/api/alerts/history').then(r => r.json()).then(alerts => alerts.forEach(a => showAlert(a)));
}

fetchHistory();
connect();