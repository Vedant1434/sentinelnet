package com.sentinelnet.core;

import com.sentinelnet.AlertRepository;
import com.sentinelnet.PersistentAlert;
import com.sentinelnet.model.PersistentFlow;
import com.sentinelnet.model.TrafficStats;
import com.sentinelnet.repository.FlowRepository;
import com.sentinelnet.repository.StatsRepository;
import com.sentinelnet.service.DpiService;
import com.sentinelnet.service.ForensicLogger;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.net.Inet4Address;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * SentinelNet Core Service - Step 8: DPI & ARP Support.
 * Changes:
 * 1. Added DpiService.
 * 2. processPacket() now handles ARP.
 * 3. FlowRecord now stores Layer 7 metadata.
 */
@Service
@Slf4j
public class SentinelNetService {

    private final ApplicationEventPublisher eventPublisher;
    private final AlertRepository alertRepository;
    private final FlowRepository flowRepository;
    private final StatsRepository statsRepository;
    private final RuleEngine ruleEngine;
    private final ForensicLogger forensicLogger;
    private final DpiService dpiService;

    // --- Pcap Resources ---
    private PcapHandle handle;
    private PcapDumper dumper;
    private volatile boolean capturing = false;
    private String currentBpfFilter = "";

    // --- Data Structures ---
    private final ConcurrentHashMap<String, FlowRecord> flowTable = new ConcurrentHashMap<>();
    private final BlockingQueue<Packet> packetQueue = new ArrayBlockingQueue<>(50000);
    private final BlockingQueue<FlowRecord> detectionQueue = new ArrayBlockingQueue<>(50000);

    // --- Thread Pools ---
    private final ExecutorService captureExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "Sentinel-Capture"));
    private final ExecutorService analysisExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "Sentinel-Analysis"));
    private final ExecutorService detectionExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "Sentinel-Detect"));

    // --- Active Defense ---
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();
    private static final String LOG_DIR = "forensic_logs";

    // --- Statistics & ML ---
    private final DescriptiveStatistics packetRateStats = new DescriptiveStatistics(100);
    private final DescriptiveStatistics flowSizeStats = new DescriptiveStatistics(1000);

    private final AtomicLong currentPacketCount = new AtomicLong(0);
    private final AtomicLong tcpCount = new AtomicLong(0);
    private final AtomicLong udpCount = new AtomicLong(0);
    private final AtomicLong icmpCount = new AtomicLong(0);

    // --- Configuration ---
    private int synFloodThreshold = 100;
    private int portScanThreshold = 50;
    private double zScoreThreshold = 3.5;

    // --- Flow Timeouts ---
    private static final long FLOW_IDLE_TIMEOUT_MS = 30_000;
    private static final long FLOW_ACTIVE_TIMEOUT_MS = 300_000;

    public SentinelNetService(ApplicationEventPublisher eventPublisher,
                              AlertRepository alertRepository,
                              FlowRepository flowRepository,
                              StatsRepository statsRepository,
                              RuleEngine ruleEngine,
                              ForensicLogger forensicLogger,
                              DpiService dpiService) {
        this.eventPublisher = eventPublisher;
        this.alertRepository = alertRepository;
        this.flowRepository = flowRepository;
        this.statsRepository = statsRepository;
        this.ruleEngine = ruleEngine;
        this.forensicLogger = forensicLogger;
        this.dpiService = dpiService;
    }

    @PostConstruct
    public void init() { startCapture(); }

    public synchronized void startCapture() {
        if (capturing) return;
        capturing = true;
        captureExecutor.submit(this::captureLoop);
        analysisExecutor.submit(this::analysisLoop);
        detectionExecutor.submit(this::detectionLoop);
    }

    @PreDestroy
    public void shutdown() {
        capturing = false;
        if (dumper != null && dumper.isOpen()) dumper.close();
        if (handle != null && handle.isOpen()) handle.close();
        captureExecutor.shutdownNow();
        analysisExecutor.shutdownNow();
        detectionExecutor.shutdownNow();
    }

    public void setBpfFilter(String filterExpression) {
        this.currentBpfFilter = filterExpression;
        if (handle != null && handle.isOpen()) {
            try {
                handle.setFilter(filterExpression, BpfProgram.BpfCompileMode.OPTIMIZE);
                log.info("BPF Filter updated to: {}", filterExpression);
            } catch (PcapNativeException | NotOpenException e) {
                log.error("Failed to set BPF Filter: {}", e.getMessage());
            }
        }
    }

    // ---------------------------------------------------------------------------
    // 1. CAPTURE LOOP
    // ---------------------------------------------------------------------------
    private void captureLoop() {
        try {
            PcapNetworkInterface nif = autoSelectInterface();
            if (nif == null) {
                log.error("CRITICAL: No network interface found.");
                return;
            }
            log.info("Starting Capture on: {}", nif.getName());
            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            if (!currentBpfFilter.isEmpty()) handle.setFilter(currentBpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
            setupForensicLogging();

            while (capturing && handle.isOpen()) {
                try {
                    Packet packet = handle.getNextPacket();
                    if (packet != null) {
                        if (dumper != null && dumper.isOpen()) dumper.dump(packet, handle.getTimestamp());
                        if (!packetQueue.offer(packet)) log.warn("Queue Full - Dropping Packet");
                        currentPacketCount.incrementAndGet();
                    }
                } catch (Exception e) { log.warn("Capture Error: {}", e.getMessage()); }
            }
        } catch (Exception e) { log.error("Fatal Capture Error", e); }
    }

    // ---------------------------------------------------------------------------
    // 2. ANALYSIS LOOP (Updated for ARP & DPI)
    // ---------------------------------------------------------------------------
    private void analysisLoop() {
        while (capturing) {
            try {
                Packet packet = packetQueue.take();
                processPacket(packet);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) { }
        }
    }

    private void processPacket(Packet packet) {
        // --- 1. HANDLE ARP ---
        ArpPacket arpPacket = packet.get(ArpPacket.class);
        if (arpPacket != null) {
            // We can optionally track ARP flows, but for now we just log interesting ones
            // or perform ARP spoofing detection (future)
            return;
        }

        // --- 2. HANDLE IPV4 ---
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet == null) return;

        String srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();
        String protocol = ipV4Packet.getHeader().getProtocol().name();

        if (blockedIps.contains(srcIp)) return;

        switch (protocol) {
            case "TCP" -> tcpCount.incrementAndGet();
            case "UDP" -> udpCount.incrementAndGet();
            case "ICMP" -> icmpCount.incrementAndGet();
        }

        boolean isSyn = false;
        int dstPort = 0;
        int payloadSize = 0;
        byte[] payloadData = null;

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            isSyn = tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck();
            dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            if(tcpPacket.getPayload() != null) {
                payloadData = tcpPacket.getPayload().getRawData();
                payloadSize = payloadData.length;
            }
        }

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if(udpPacket != null) {
            dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
            if(udpPacket.getPayload() != null) {
                payloadData = udpPacket.getPayload().getRawData();
                payloadSize = payloadData.length;
            }
        }

        // --- 3. DPI INSPECTION ---
        String appInfo = null;
        if (payloadData != null && payloadData.length > 0) {
            appInfo = dpiService.inspect(payloadData, protocol, dstPort);
        }

        String flowKey = srcIp + "->" + dstIp + "/" + protocol;
        boolean finalIsSyn = isSyn;
        int finalDstPort = dstPort;
        int finalPayloadSize = payloadSize;
        String finalAppInfo = appInfo;

        FlowRecord flow = flowTable.compute(flowKey, (k, f) -> {
            if (f == null) f = new FlowRecord(srcIp, dstIp, protocol);
            f.update(packet.length(), finalIsSyn, finalDstPort, finalPayloadSize, finalAppInfo);
            return f;
        });

        flowSizeStats.addValue(flow.getBytes());
        if (!detectionQueue.offer(flow)) { /* Drop if busy */ }
    }

    // ---------------------------------------------------------------------------
    // 3. DETECTION LOOP
    // ---------------------------------------------------------------------------
    private void detectionLoop() {
        while (capturing) {
            try {
                FlowRecord flow = detectionQueue.take();
                checkSignatures(flow);
                checkHeuristics(flow);
                checkProtocolAnomalies(flow);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void checkSignatures(FlowRecord flow) {
        Optional<DetectionRule> matchedRule = ruleEngine.evaluate(flow);
        if (matchedRule.isPresent()) {
            DetectionRule rule = matchedRule.get();
            if (flow.getPacketCount() % 50 == 0) {
                publishAlert("RULE MATCH: " + rule.getName(), rule.getDescription(), rule.getSeverity());
            }
        }
    }

    private void checkHeuristics(FlowRecord flow) {
        if (flow.getSynCount() > synFloodThreshold) {
            publishAlert("SYN FLOOD", "High SYN rate ("+flow.getSynCount()+") from " + flow.srcIp, "CRITICAL");
            flow.setSynCount(0);
        }
        if (flow.getUniquePorts().size() > portScanThreshold) {
            publishAlert("PORT SCAN", "Vertical scan detected from " + flow.srcIp, "HIGH");
            flow.getUniquePorts().clear();
        }
    }

    private void checkProtocolAnomalies(FlowRecord flow) {
        if (flow.getProtocol().equals("UDP") && flow.getUniquePorts().contains(53)) {
            if (flow.getMaxPayloadSize() > 200) {
                publishAlert("DNS TUNNELING", "Suspiciously large DNS packet (" + flow.getMaxPayloadSize() + " bytes)", "HIGH");
            }
        }
        if (flow.getProtocol().equals("ICMP")) {
            if (flow.getBytes() > 10000 && flow.getPacketCount() > 50) {
                publishAlert("ICMP FLOOD", "Large volume of ICMP traffic", "MEDIUM");
            }
        }
    }

    // ---------------------------------------------------------------------------
    // 4. STATS, HOUSEKEEPING & PERSISTENCE
    // ---------------------------------------------------------------------------
    @Scheduled(fixedRate = 5000)
    public void manageFlowLifecycle() {
        long now = System.currentTimeMillis();
        flowTable.entrySet().removeIf(entry -> {
            FlowRecord f = entry.getValue();
            boolean expired = (now - f.getLastSeen() > FLOW_IDLE_TIMEOUT_MS) ||
                    (now - f.getStartTime() > FLOW_ACTIVE_TIMEOUT_MS);

            if (expired) {
                try {
                    PersistentFlow dbFlow = new PersistentFlow(
                            f.getSrcIp(), f.getDstIp(), f.getProtocol(),
                            f.getPacketCount(), f.getBytes(), f.getSynCount(),
                            f.getStartTime(), f.getLastSeen()
                    );
                    flowRepository.save(dbFlow);

                    if (f.getBytes() > 1000000 || f.getPacketCount() > 1000) {
                        Map<String, Object> details = new HashMap<>();
                        details.put("src", f.getSrcIp());
                        details.put("dst", f.getDstIp());
                        details.put("proto", f.getProtocol());
                        details.put("metadata", f.getMetadata()); // Log DPI data!
                        details.put("bytes", f.getBytes());
                        details.put("duration", f.getLastSeen() - f.getStartTime());
                        forensicLogger.logEvent("FLOW", "FLOW_EXPIRY", "INFO", details);
                    }
                } catch (Exception e) {
                    log.error("Error saving expired flow", e);
                }
            }
            return expired;
        });
    }

    @Scheduled(fixedRate = 1000)
    public void broadcastStats() {
        long currentRate = currentPacketCount.getAndSet(0);
        packetRateStats.addValue(currentRate);

        if (packetRateStats.getN() > 10 && packetRateStats.getStandardDeviation() > 0) {
            double zScore = (currentRate - packetRateStats.getMean()) / packetRateStats.getStandardDeviation();
            if (Math.abs(zScore) > zScoreThreshold) {
                publishAlert("TRAFFIC ANOMALY", "Traffic Volume Z-Score: " + String.format("%.2f", zScore), "MEDIUM");
            }
        }

        long currentBandwidth = currentRate * 800 * 8;

        try {
            TrafficStats stats = new TrafficStats(
                    null, new Date(), currentRate, currentBandwidth,
                    flowTable.size(), tcpCount.get(), udpCount.get(), icmpCount.get()
            );
            statsRepository.save(stats);
        } catch (Exception e) {
            log.error("Error saving stats", e);
        }

        Map<Integer, Long> portCounts = flowTable.values().stream()
                .flatMap(f -> f.getUniquePorts().stream())
                .collect(Collectors.groupingBy(p -> p, Collectors.counting()));

        Map<Integer, Long> topPorts = portCounts.entrySet().stream()
                .sorted(Map.Entry.<Integer, Long>comparingByValue().reversed())
                .limit(5)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1, LinkedHashMap::new));

        Map<String, Object> statsMap = new HashMap<>();
        statsMap.put("pps", currentRate);
        statsMap.put("activeFlows", flowTable.size());
        statsMap.put("bandwidth", currentBandwidth);
        statsMap.put("tcp", tcpCount.get());
        statsMap.put("udp", udpCount.get());
        statsMap.put("icmp", icmpCount.get());
        statsMap.put("topPorts", topPorts);

        eventPublisher.publishEvent(new StatsEvent(this, statsMap));

        List<FlowRecord> topFlows = flowTable.values().stream()
                .sorted((f1, f2) -> Long.compare(f2.getPacketCount(), f1.getPacketCount()))
                .limit(15)
                .collect(Collectors.toList());

        eventPublisher.publishEvent(new FlowsEvent(this, topFlows));
    }

    private void setupForensicLogging() {
        File logDir = new File(LOG_DIR);
        if (!logDir.exists()) logDir.mkdirs();
        try {
            dumper = handle.dumpOpen(LOG_DIR + File.separator + "capture_" + System.currentTimeMillis() + ".pcap");
        } catch (PcapNativeException | NotOpenException e) {
            log.warn("Failed to open dump file: {}", e.getMessage());
        }
    }

    private PcapNetworkInterface autoSelectInterface() {
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            for (PcapNetworkInterface dev : allDevs) {
                if (dev.getName().toLowerCase().contains("loopback")) continue;
                for (PcapAddress addr : dev.getAddresses()) {
                    if (addr.getAddress() instanceof Inet4Address) {
                        String ip = addr.getAddress().getHostAddress();
                        if (!ip.equals("0.0.0.0") && !ip.equals("127.0.0.1") && !ip.startsWith("169.254")) return dev;
                    }
                }
            }
            return allDevs.isEmpty() ? null : allDevs.get(0);
        } catch (PcapNativeException e) { return null; }
    }

    private void publishAlert(String type, String message, String severity) {
        log.warn("IDS ALERT [{}]: {}", severity, message);
        Map<String, Object> details = new HashMap<>();
        details.put("message", message);
        forensicLogger.logEvent("ALERT", type, severity, details);
        try {
            PersistentAlert dbAlert = new PersistentAlert(null, type, message, severity, new Date().toString());
            alertRepository.save(dbAlert);
            eventPublisher.publishEvent(new AlertEvent(this, new Alert(type, message, severity, new Date())));
        } catch (Exception e) { log.error("Failed to save alert", e); }
    }

    // --- API Accessors ---
    public Collection<FlowRecord> getActiveFlows() { return flowTable.values(); }
    public void blockIp(String ip) { blockedIps.add(ip); publishAlert("MANUAL BLOCK", "Admin blocked " + ip, "HIGH"); }
    public void unblockIp(String ip) { blockedIps.remove(ip); }
    public Set<String> getBlockedIps() { return blockedIps; }
    public int getSynFloodThreshold() { return synFloodThreshold; }
    public void setSynFloodThreshold(int val) { this.synFloodThreshold = val; }
    public int getPortScanThreshold() { return portScanThreshold; }
    public void setPortScanThreshold(int val) { this.portScanThreshold = val; }
    public double getZScoreThreshold() { return zScoreThreshold; }
    public void setZScoreThreshold(double val) { this.zScoreThreshold = val; }

    // ---------------------------------------------------------------------------
    // 5. DTOs & EVENTS
    // ---------------------------------------------------------------------------
    public static class FlowRecord {
        private String srcIp; private String dstIp; private String protocol;
        private long packetCount; private long bytes; private int synCount;
        private int maxPayloadSize = 0;
        private Set<Integer> uniquePorts = ConcurrentHashMap.newKeySet();
        private long firstSeen; private long lastSeen;
        private String metadata; // New Field for DPI info

        public FlowRecord(String s, String d, String p) {
            this.srcIp = s; this.dstIp = d; this.protocol = p;
            this.firstSeen = System.currentTimeMillis(); this.lastSeen = System.currentTimeMillis();
        }
        public void update(long len, boolean isSyn, int port, int payloadSize, String appInfo) {
            this.packetCount++; this.bytes += len; this.lastSeen = System.currentTimeMillis();
            if (isSyn) this.synCount++;
            if (port > 0) this.uniquePorts.add(port);
            if (payloadSize > this.maxPayloadSize) this.maxPayloadSize = payloadSize;
            if (appInfo != null) this.metadata = appInfo; // Store DPI result if found
        }
        public String getSrcIp() { return srcIp; }
        public String getDstIp() { return dstIp; }
        public String getProtocol() { return protocol; }
        public long getPacketCount() { return packetCount; }
        public long getBytes() { return bytes; }
        public int getSynCount() { return synCount; }
        public Set<Integer> getUniquePorts() { return uniquePorts; }
        public int getMaxPayloadSize() { return maxPayloadSize; }
        public long getLastSeen() { return lastSeen; }
        public long getStartTime() { return firstSeen; }
        public String getMetadata() { return metadata; } // Getter for frontend
        public void setSynCount(int s) { this.synCount = s; }
    }

    public static class Alert {
        private String type; private String description; private String severity; private Date timestamp;
        public Alert(String type, String description, String severity, Date timestamp) {
            this.type = type; this.description = description; this.severity = severity; this.timestamp = timestamp;
        }
        public String getType() { return type; }
        public String getDescription() { return description; }
        public String getSeverity() { return severity; }
        public Date getTimestamp() { return timestamp; }
    }
    public static class AlertEvent extends ApplicationEvent {
        private final Alert alert;
        public AlertEvent(Object source, Alert alert) { super(source); this.alert = alert; }
        public Alert getAlert() { return alert; }
    }
    public static class StatsEvent extends ApplicationEvent {
        private final Map<String, Object> stats;
        public StatsEvent(Object source, Map<String, Object> stats) { super(source); this.stats = stats; }
        public Map<String, Object> getStats() { return stats; }
    }
    public static class FlowsEvent extends ApplicationEvent {
        private final List<FlowRecord> flows;
        public FlowsEvent(Object source, List<FlowRecord> flows) { super(source); this.flows = flows; }
        public List<FlowRecord> getFlows() { return flows; }
    }
}