// --- Traffic Line Chart ---
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Packets Per Second',
            data: [],
            borderColor: '#3498db',
            tension: 0.3,
            fill: true,
            backgroundColor: 'rgba(52, 152, 219, 0.1)'
        }]
    },
    options: { responsive: true, scales: { x: { display: false }, y: { beginAtZero: true } } }
});

// --- Protocol Pie Chart ---
const protoCtx = document.getElementById('protoChart').getContext('2d');
const protoChart = new Chart(protoCtx, {
    type: 'doughnut',
    data: {
        labels: ['TCP', 'UDP', 'ICMP'],
        datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['#2ecc71', '#e67e22', '#e74c3c']
        }]
    }
});

// --- WebSocket ---
let stompClient = null;

function connect() {
    const socket = new SockJS('/ws-sentinel');
    stompClient = Stomp.over(socket);
    stompClient.debug = null;

    stompClient.connect({}, function (frame) {
        document.getElementById('connStatus').innerText = 'Online';

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
    document.getElementById('bwValue').innerText = formatBytes(stats.bandwidth);
    document.getElementById('flowValue').innerText = stats.activeFlows;

    const now = new Date().toLocaleTimeString();
    if (trafficChart.data.labels.length > 20) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
    }
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(stats.pps);
    trafficChart.update();

    protoChart.data.datasets[0].data = [stats.tcp, stats.udp, stats.icmp];
    protoChart.update();
}

function showAlert(alert) {
    const container = document.getElementById('alertContainer');
    if(container.innerText.includes("Listening")) container.innerHTML = "";

    const div = document.createElement('div');
    div.className = `alert-item alert-${alert.severity}`;
    div.innerHTML = `<strong>${alert.type}</strong><br>${alert.description} <br> <small class="text-muted">${new Date(alert.timestamp).toLocaleTimeString()}</small>`;

    container.insertBefore(div, container.firstChild);

    const threatLabel = document.getElementById('statusValue');
    if(alert.severity === 'CRITICAL' || alert.severity === 'HIGH') {
        threatLabel.innerText = "UNDER ATTACK";
        threatLabel.className = "metric-value text-danger";
        setTimeout(() => {
             threatLabel.innerText = "SECURE";
             threatLabel.className = "metric-value text-success";
        }, 5000);
    }
}

function fetchHistory() {
    fetch('/api/alerts/history')
        .then(r => r.json())
        .then(alerts => {
            alerts.forEach(a => showAlert(a));
        });
}

function fetchFlows() {
    fetch('/api/flows').then(r => r.json()).then(flows => {
        const tbody = document.getElementById('flowTableBody');
        tbody.innerHTML = '';
        flows.slice(0, 8).forEach(flow => {
            tbody.innerHTML += `<tr><td>${flow.srcIp}</td><td>${flow.dstIp}</td><td>${flow.protocol}</td><td>${flow.packetCount}</td></tr>`;
        });
    });
}

function formatBytes(bits) {
    if(bits === 0) return '0 bps';
    const k = 1024;
    const i = Math.floor(Math.log(bits) / Math.log(k));
    return parseFloat((bits / Math.pow(k, i)).toFixed(2)) + ' ' + ['bps', 'Kbps', 'Mbps', 'Gbps'][i];
}

// --- Navigation Logic ---
function showSection(sectionId) {
    // Hide all sections
    document.getElementById('dashboardSection').classList.add('d-none');
    document.getElementById('forensicsSection').classList.add('d-none');
    document.getElementById('settingsSection').classList.add('d-none');

    // Show selected
    document.getElementById(sectionId + 'Section').classList.remove('d-none');

    // Load data if needed
    if(sectionId === 'forensics') loadForensics();
    if(sectionId === 'settings') loadSettings();
}

// --- Forensics Logic ---
function loadForensics() {
    fetch('/api/forensics')
        .then(r => r.json())
        .then(files => {
            const tbody = document.getElementById('forensicsTableBody');
            tbody.innerHTML = '';
            files.forEach(file => {
                tbody.innerHTML += `
                    <tr>
                        <td>${file}</td>
                        <td><a href="/api/forensics/download/${file}" class="btn btn-sm btn-outline-primary" target="_blank">Download</a></td>
                    </tr>
                `;
            });
        });
}

// --- Settings Logic ---
function loadSettings() {
    fetch('/api/settings')
        .then(r => r.json())
        .then(settings => {
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

    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
    }).then(r => {
        if(r.ok) alert("Configuration saved successfully!");
        else alert("Failed to save configuration.");
    });
}

// Start
connect();
setInterval(fetchFlows, 2000);