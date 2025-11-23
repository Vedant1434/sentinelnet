// --- Configuration ---
// Set this to your server's real/approximate location for the "Target" point
const MY_LOC = { lat: 28.6139, lon: 77.2090 }; // Example: New Delhi

// --- Initialize Leaflet Map ---
const map = L.map('map', {
    zoomControl: false,
    attributionControl: false,
    preferCanvas: true
}).setView([25, 10], 3);

// Dark High-Contrast Tiles
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd',
    maxZoom: 19
}).addTo(map);

// Add Target Marker (Your Location)
const targetIcon = L.divIcon({
    className: 'target-icon',
    html: `<div style="
        width: 14px; height: 14px;
        background: #00f3ff; border-radius: 50%;
        box-shadow: 0 0 20px #00f3ff, 0 0 40px #00f3ff;
        animation: pulse 2s infinite;">
    </div>`,
    iconSize: [14, 14],
    iconAnchor: [7, 7]
});
L.marker([MY_LOC.lat, MY_LOC.lon], { icon: targetIcon }).addTo(map)
    .bindPopup("<b>SENTINEL HQ</b><br>System Operational");

// --- Data Structures ---
const countryStats = {};
const activeMarkers = {}; // Map of IP -> Leaflet Marker

// --- WebSocket Connection ---
const socket = new SockJS('/ws-sentinel');
const stompClient = Stomp.over(socket);
stompClient.debug = null;

stompClient.connect({}, function (frame) {
    console.log("Connected to Live Map Stream");

    stompClient.subscribe('/topic/flows', function (data) {
        const flows = JSON.parse(data.body);
        updateMap(flows);
    });
}, function(error) {
    console.error("Stream Error", error);
});

function updateMap(flows) {
    flows.forEach(flow => {
        if (!flow.geoLocation || !flow.geoLocation.lat) return;

        const srcLat = flow.geoLocation.lat;
        const srcLon = flow.geoLocation.lon;
        const country = flow.geoLocation.countryCode || "UNK";
        const ip = flow.srcIp;

        // 1. Update Stats
        if (!countryStats[country]) countryStats[country] = 0;
        countryStats[country]++;
        updateStatsPanel();

        // 2. Add/Update Feed
        addFeedItem(flow, country);

        // 3. Visualize on Map
        // Only animate if it's a "remote" connection (not localhost)
        if (Math.abs(srcLat - MY_LOC.lat) > 0.5 || Math.abs(srcLon - MY_LOC.lon) > 0.5) {
            animateConnection(srcLat, srcLon, flow);
        }
    });
}

function animateConnection(lat, lon, flow) {
    // Draw Source Pulse
    const color = '#bc13fe'; // Purple for generic traffic

    // Create Arc (Bezier Curve)
    // We add some randomness to the control point to make lines look organic
    const midLat = (lat + MY_LOC.lat) / 2 + (Math.random() * 10 - 5);
    const midLon = (lon + MY_LOC.lon) / 2 + (Math.random() * 10 - 5);

    const pathData = [
        'M', [lat, lon], // Start
        'Q', [midLat, midLon], // Control Point
        [MY_LOC.lat, MY_LOC.lon] // End
    ];

    const curve = L.curve(pathData, {
        color: color,
        weight: 1.5,
        opacity: 0, // Start hidden for animation
        animate: {
            duration: 1500,
            iterations: 1,
            easing: 'ease-in-out'
        }
    }).addTo(map);

    // Draw Source Marker (Temporary)
    const sourceMarker = L.circleMarker([lat, lon], {
        radius: 4,
        color: color,
        fillColor: color,
        fillOpacity: 0.8
    }).addTo(map);

    // Tooltip on Hover
    sourceMarker.bindTooltip(`
        <div style="text-align:center;">
            <b>${flow.srcIp}</b><br>
            ${flow.geoLocation.country}<br>
            ${flow.protocol} - ${formatBytes(flow.bytes)}
        </div>
    `, { direction: 'top', offset: [0, -5], className: 'custom-tooltip' });

    // Cleanup animation artifacts after they finish
    setTimeout(() => {
        map.removeLayer(curve);

        // Fade out marker slowly
        let op = 0.8;
        const fade = setInterval(() => {
            if (op <= 0) {
                clearInterval(fade);
                map.removeLayer(sourceMarker);
            } else {
                op -= 0.1;
                sourceMarker.setStyle({ fillOpacity: op, opacity: op });
            }
        }, 100);
    }, 2000);
}

function addFeedItem(flow, country) {
    const container = document.getElementById('feedContainer');
    const div = document.createElement('div');
    div.className = 'feed-item inbound';

    // Use Flag API for visuals
    const flagUrl = country !== 'UNK' ? `https://flagcdn.com/16x12/${country.toLowerCase()}.png` : '';
    const flagImg = flagUrl ? `<img src="${flagUrl}" style="vertical-align: middle; margin-right: 5px;">` : '';

    div.innerHTML = `
        <div class="ip">${flagImg} ${flow.srcIp}</div>
        <div class="details">
            <span>${flow.protocol}</span>
            <span>${formatBytes(flow.bytes)}</span>
        </div>
    `;

    container.insertBefore(div, container.firstChild); // Add to top

    // Limit items to prevent lag
    if (container.children.length > 15) {
        container.removeChild(container.lastChild);
    }
}

function updateStatsPanel() {
    const container = document.getElementById('topCountries');
    const sorted = Object.entries(countryStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    if (sorted.length === 0) return;

    container.innerHTML = sorted.map(([code, count]) => {
        const flagUrl = code !== 'UNK' ? `https://flagcdn.com/16x12/${code.toLowerCase()}.png` : '';
        const imgTag = flagUrl ? `<img src="${flagUrl}">` : '<i class="fas fa-question-circle text-muted"></i>';
        return `
            <div class="stat-row">
                <span>${imgTag} &nbsp;${code}</span>
                <span class="stat-val">${count}</span>
            </div>
        `;
    }).join('');
}

function formatBytes(bits) {
    if(bits === 0) return '0 b';
    const k = 1024;
    const i = Math.floor(Math.log(bits) / Math.log(k));
    const sizes = ['b', 'Kb', 'Mb', 'Gb', 'Tb'];
    return parseFloat((bits / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// CSS Animation for Pulse (Injected via JS for simplicity with Leaflet DivIcon)
const style = document.createElement('style');
style.innerHTML = `
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(0, 243, 255, 0.7); }
        70% { box-shadow: 0 0 0 15px rgba(0, 243, 255, 0); }
        100% { box-shadow: 0 0 0 0 rgba(0, 243, 255, 0); }
    }
`;
document.head.appendChild(style);