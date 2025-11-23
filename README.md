# SentinelNet: Real-Time Network Security Monitor & IDS

**SentinelNet** is a high-performance, Java-based Network Intrusion Detection System (IDS) and Traffic Monitor built with Spring Boot. It provides real-time visibility into network traffic, detects potential threats using a hybrid engine (signature-based + heuristic), and offers active defense capabilities through automated IP blocking.

Designed as a "Security Operations Center (SOC) in a box," SentinelNet captures raw packets from the wire, reassembles them into flows, performs Deep Packet Inspection (DPI), and visualizes threats on a live interactive dashboard.

---

## 📖 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [System Architecture](#-system-architecture)
4. [Theoretical Concepts](#-theoretical-concepts)
5. [Project Structure](#-project-structure)
6. [Prerequisites & Installation](#-prerequisites--installation)
7. [Usage Guide](#-usage-guide)
8. [Configuration](#-configuration)
9. [Future Improvements](#-future-improvements)

---

## 🔭 Project Overview

SentinelNet bridges the gap between low-level packet capture and high-level security analytics. Unlike standard firewalls that filter based on ports, SentinelNet inspects the actual content of packets to identify application-layer protocols and malicious patterns.

It operates by placing the network interface in **promiscuous mode**, allowing it to analyze all traffic passing through the host—not just traffic destined for it.

---

## 🚀 Key Features

### 1. Real-Time Traffic Monitoring
- **Packet Capture:** Uses `Pcap4j` to capture Ethernet/IP packets directly from the network interface.
- **Flow Analysis:** Aggregates packets into 5-tuple "Flows" (Src IP, Dst IP, Protocol, Src/Dst Ports) to calculate bandwidth and packet rates.
- **Geo-Location:** Resolves IP addresses to physical countries using the `ip-api.com` service for a live threat map.

### 2. Hybrid Intrusion Detection Engine
- **Signature-Based Detection:** Evaluates traffic against a configurable JSON ruleset (e.g., "Block SSH Brute Force", "Alert on large HTTP transfers").
- **Heuristic Analysis:**
    - **SYN Flood Detection:** Identifies IPs sending excessive SYN packets without completing the TCP handshake.
    - **Port Scan Detection:** Flags IPs connecting to multiple distinct ports in a short time window.
- **Statistical Anomaly Detection:** Uses Z-Score analysis to detect traffic volume spikes that deviate significantly from the moving average.

### 3. Deep Packet Inspection (DPI)
- Inspects Layer 7 payloads to identify protocols (HTTP methods, SSH versions, TLS handshakes) regardless of the non-standard ports they might use.

### 4. Active Defense & Forensics
- **Automated Blocking:** Capable of automatically "blocking" (dropping internally) IPs that trigger critical severity rules.
- **Forensic Logging:** Records full `.pcap` files and JSON audit logs (`forensic_logs/audit.jsonl`) for post-incident analysis.

### 5. Interactive Dashboard
- **Live Visualization:** Web-based UI (Thymeleaf + Bootstrap) with real-time charts (Chart.js) updated via WebSockets (STOMP).
- **Threat Map:** A 3D-style live connection map using Leaflet.js.

---

## 🏗️ System Architecture

The application utilizes a **multi-threaded pipeline** to ensure packet capture does not block analysis or the user interface.

1.  **Capture Thread (`Sentinel-Capture`)**:
    - Reads raw packets using `PcapHandle`.
    - Dumps packets to disk for forensics.
    - Pushes packets to a high-performance `BlockingQueue`.

2.  **Analysis Thread (`Sentinel-Analysis`)**:
    - Dequeues packets and parses headers (Ethernet, IPv4, TCP/UDP).
    - Performs **Deep Packet Inspection (DPI)** on payloads.
    - Aggregates data into the `FlowTable` (ConcurrentHashMap).
    - Updates flow statistics (Bytes, Packets, SYN counts).

3.  **Detection Thread (`Sentinel-Detect`)**:
    - Periodically scans active flows.
    - Evaluates flows against `DetectionRules` and Heuristic thresholds.
    - Triggers alerts (`PersistentAlert`) and updates the database.

4.  **Presentation Layer**:
    - **Spring MVC Controllers**: Serve REST endpoints and HTML views.
    - **WebSocket Service**: Pushes `StatsEvent`, `AlertEvent`, and `FlowsEvent` to the frontend subscribers (`/topic/stats`, etc.).

---

## 🧠 Theoretical Concepts

### 1. Promiscuous Mode
Normally, a network card drops packets not addressed to its MAC address. SentinelNet forces the card into *promiscuous mode*, enabling it to "sniff" all traffic on the local segment.

### 2. The 5-Tuple Flow
Instead of analyzing packets in isolation, the system groups them into **Flows**:
`{Source IP, Destination IP, Protocol, Source Port, Destination Port}`.
This allows the system to track connection states (e.g., "Is this an established SSH session or just a random packet?").

### 3. Z-Score Anomaly Detection
To detect DDoS attacks without setting arbitrary hard limits, the system calculates the **Z-Score** of the packet rate:
$$Z = \frac{(Current Rate - Moving Average)}{Standard Deviation}$$
A Z-Score > 3.5 indicates a statistical anomaly (99.9% probability of deviation), triggering a "Traffic Anomaly" alert.

### 4. TCP 3-Way Handshake & SYN Floods
The system monitors TCP flags. A normal connection is `SYN` -> `SYN-ACK` -> `ACK`.
A **SYN Flood** occurs when an attacker sends many `SYN` packets but never sends the final `ACK`. SentinelNet counts the "unacknowledged SYNs" per flow to detect this.

---

## 📂 Project Structure

```bash
src/main/java/com/sentinelnet
├── SentinelNetApplication.java   # Entry Point
├── core
│   ├── SentinelNetService.java   # Main Engine (Capture/Analysis/Detect)
│   ├── RuleEngine.java           # Signature Logic
│   └── DetectionRule.java        # Rule Model
├── model                         # JPA Entities (PersistentFlow, TrafficStats)
├── repository                    # Spring Data Repositories
├── service
│   ├── DpiService.java           # Layer 7 Inspection
│   ├── GeoIpService.java         # IP Geolocation
│   └── ForensicLogger.java       # Audit Logging
└── web
    ├── AlertController.java      # API for Alerts
    ├── DashboardPushService.java # WebSocket Broadcaster
    └── MapController.java        # Threat Map View

src/main/resources
```
## 💻 Prerequisites & Installation

### Prerequisites
1.  **Java 21** (JDK)
2.  **Maven** (3.6+)
3.  **PostgreSQL** (or Docker to run it)
4.  **PCAP Library**:
    - **Windows:** Install [Npcap](https://npcap.com/) (Ensure "Install in API-compatible Mode" is checked).
    - **Linux/Mac:** Install `libpcap` (usually pre-installed or `sudo apt-get install libpcap-dev`).

### Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/your-repo/sentinelnet.git](https://github.com/your-repo/sentinelnet.git)
    cd sentinelnet
    ```

2.  **Start Database**
    Use the included Docker Compose file to start PostgreSQL:
    ```bash
    docker-compose up -d
    ```
    *Note: Maps internal port 5432 to host port **5433**.*

3.  **Build the Project**
    ```bash
    mvn clean install
    ```

---

## 🎮 Usage Guide

### Running the Application
**Note:** Packet capture requires **Root/Administrator** privileges.

- **Windows:** Open Command Prompt as **Administrator**.
- **Linux/Mac:** Use `sudo`.

```bash
# Run using the built JAR
java -jar target/sentinelnet-1.0-SNAPSHOT.jar
├── application.properties        # DB & App Config
├── rules.json                    # Detection Signatures
└── templates                     # HTML Views
```
### Accessing the Dashboard
Open your web browser and navigate to:
`http://localhost:8080`

### Features Breakdown
- **Dashboard:** View real-time traffic graphs, top ports, and IDS alerts.
- **Attack Map:** Click "Connection Map" in the sidebar to view the live 3D globe.
- **Forensics:** Click "Forensics" to download `.pcap` files or the Audit Log (`audit.jsonl`).
- **Configuration:** Adjust thresholds (SYN Flood limit, Z-Score sensitivity) dynamically via the Settings page.

---

## ⚙️ Configuration

### Detection Rules (`src/main/resources/rules.json`)
You can add custom signature rules in this JSON file.

```json
{
  "id": "SIG-9001",
  "name": "Block Admin Panel Access",
  "description": "Detects access to sensitive admin paths",
  "severity": "CRITICAL",
  "protocol": "TCP",
  "targetPort": 8080,
  "minPacketCount": 1,
  "action": "BLOCK"
}
```
### Application Settings (`application.properties`)
- **Server Port:** `server.port=8080`
- **Database:** `spring.datasource.url=jdbc:postgresql://localhost:5433/sentinelnet`

---

## 🔮 Future Improvements

1.  **System Firewall Integration:**
    Currently, "Blocking" stops processing within the app. Future versions could hook into `iptables` (Linux) or `Windows Firewall` to drop packets at the OS level.

2.  **Encrypted Traffic Analysis (ETA):**
    Implement **JA3 Fingerprinting** to identify malicious clients based on their TLS handshake parameters, even when the traffic is encrypted.

3.  **Machine Learning:**
    Replace the Z-Score statistic with an **Isolation Forest** model to detect complex, non-linear anomalies in traffic patterns.

4.  **Distributed Sensors:**
    Decouple the Capture Engine from the Analysis Core, allowing lightweight sensors to be deployed across a network, feeding data to a central SentinelNet server.
