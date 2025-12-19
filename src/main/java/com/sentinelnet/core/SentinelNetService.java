package com.sentinelnet.core;

import com.sentinelnet.AlertRepository;
import com.sentinelnet.PersistentAlert;
import com.sentinelnet.model.PersistentFlow;
import com.sentinelnet.model.TrafficStats;
import com.sentinelnet.repository.FlowRepository;
import com.sentinelnet.repository.StatsRepository;
import com.sentinelnet.service.DpiService;
import com.sentinelnet.service.ForensicLogger;
import com.sentinelnet.service.GeoIpService;
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
    private final GeoIpService geoIpService;

    private PcapHandle handle;
    private PcapDumper dumper;
    private volatile boolean capturing = false;
    private String currentBpfFilter = "";

    private final ConcurrentHashMap<String, FlowRecord> flowTable = new ConcurrentHashMap<>();
    private final BlockingQueue<Packet> packetQueue = new ArrayBlockingQueue<>(50000);
    private final BlockingQueue<FlowRecord> detectionQueue = new ArrayBlockingQueue<>(50000);

    private final ExecutorService captureExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "Sentinel-Capture"));
    private final ExecutorService analysisExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "Sentinel-Analysis"));
    private final ExecutorService detectionExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "Sentinel-Detect"));

    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();
    private static final String LOG_DIR = "forensic_logs";

    private final DescriptiveStatistics packetRateStats = new DescriptiveStatistics(100);
    private final DescriptiveStatistics flowSizeStats = new DescriptiveStatistics(1000);

    private final AtomicLong currentPacketCount = new AtomicLong(0);
    private final AtomicLong tcpCount = new AtomicLong(0);
    private final AtomicLong udpCount = new AtomicLong(0);
    private final AtomicLong icmpCount = new AtomicLong(0);

    // Configuration
    private static final int DEFAULT_SYN_THRESHOLD = 100;
    private static final int DEFAULT_SCAN_THRESHOLD = 50;
    private static final double DEFAULT_ZSCORE_THRESHOLD = 3.5;

    private int synFloodThreshold = DEFAULT_SYN_THRESHOLD;
    private int portScanThreshold = DEFAULT_SCAN_THRESHOLD;
    private double zScoreThreshold = DEFAULT_ZSCORE_THRESHOLD;

    private static final long FLOW_IDLE_TIMEOUT_MS = 30_000;
    private static final long FLOW_ACTIVE_TIMEOUT_MS = 300_000;

    public SentinelNetService(ApplicationEventPublisher eventPublisher,
                              AlertRepository alertRepository,
                              FlowRepository flowRepository,
                              StatsRepository statsRepository,
                              RuleEngine ruleEngine,
                              ForensicLogger forensicLogger,
                              DpiService dpiService,
                              GeoIpService geoIpService) {
        this.eventPublisher = eventPublisher;
        this.alertRepository = alertRepository;
        this.flowRepository = flowRepository;
        this.statsRepository = statsRepository;
        this.ruleEngine = ruleEngine;
        this.forensicLogger = forensicLogger;
        this.dpiService = dpiService;
        this.geoIpService = geoIpService;
    }

    @PostConstruct
    public void init() { startCapture(); }

    public void resetConfiguration() {
        this.synFloodThreshold = DEFAULT_SYN_THRESHOLD;
        this.portScanThreshold = DEFAULT_SCAN_THRESHOLD;
        this.zScoreThreshold = DEFAULT_ZSCORE_THRESHOLD;
        log.info("Configuration reset to defaults.");
    }

    public synchronized void startCapture() {
        if (capturing) {
            log.info("Capture already running.");
            return;
        }
        capturing = true;
        log.info("Starting Capture Engine...");
        captureExecutor.submit(this::captureLoop);
        analysisExecutor.submit(this::analysisLoop);
        detectionExecutor.submit(this::detectionLoop);
    }

    public synchronized void stopCapture() {
        if (!capturing) return;
        log.info("Stopping Capture Engine...");
        capturing = false;
        if (handle != null && handle.isOpen()) {
            try { handle.close(); } catch (Exception e) { log.error("Error closing handle", e); }
        }
        if (dumper != null && dumper.isOpen()) dumper.close();
    }

    public boolean isCapturing() { return capturing; }
    public String getCurrentFilter() { return currentBpfFilter; }

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

    @PreDestroy
    public void shutdown() {
        stopCapture();
        captureExecutor.shutdownNow();
        analysisExecutor.shutdownNow();
        detectionExecutor.shutdownNow();
    }

    // --- CAPTURE LOOP ---
    private void captureLoop() {
        try {
            PcapNetworkInterface nif = autoSelectInterface();
            if (nif == null) {
                log.error("CRITICAL: No valid network interface found.");
                capturing = false;
                return;
            }
            log.info(">>> CAPTURING ON: {} ({})", nif.getDescription(), nif.getName());

            // Open with promiscuous mode, larger snaplen, and short timeout
            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            if (!currentBpfFilter.isEmpty()) handle.setFilter(currentBpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);

            setupForensicLogging();

            while (capturing && handle.isOpen()) {
                try {
                    Packet packet = handle.getNextPacket();
                    if (packet != null) {
                        if (dumper != null && dumper.isOpen()) dumper.dump(packet, handle.getTimestamp());
                        if (!packetQueue.offer(packet)) log.warn("Queue Full - Dropping Packet");

                        long count = currentPacketCount.incrementAndGet();
                        if (count % 100 == 0) log.debug("Captured {} packets so far...", count);
                    }
                } catch (Exception e) { if (capturing) log.warn("Capture Packet Error: {}", e.getMessage()); }
            }
        } catch (Exception e) { log.error("Fatal Capture Error", e); capturing = false; }
        log.info("Capture Loop Stopped");
    }

    // --- SMART INTERFACE SELECTION ---
    private PcapNetworkInterface autoSelectInterface() {
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (allDevs == null || allDevs.isEmpty()) {
                log.error("No network interfaces found by Pcap4j!");
                return null;
            }

            log.info("--- Scanning Network Interfaces ---");
            PcapNetworkInterface bestCandidate = null;

            for (PcapNetworkInterface dev : allDevs) {
                String name = dev.getName().toLowerCase();
                String desc = (dev.getDescription() != null) ? dev.getDescription().toLowerCase() : "";

                boolean isLoopback = name.contains("loopback");
                boolean isVirtual = desc.contains("virtual") || desc.contains("vmware") || desc.contains("hyper-v");
                boolean isRealNetwork = desc.contains("wi-fi") || desc.contains("wireless") || desc.contains("ethernet") || desc.contains("controller") || desc.contains("network adapter");

                boolean hasIp = false;
                for (PcapAddress addr : dev.getAddresses()) {
                    if (addr.getAddress() instanceof Inet4Address) {
                        String ip = addr.getAddress().getHostAddress();
                        if (!ip.equals("0.0.0.0") && !ip.equals("127.0.0.1") && !ip.startsWith("169.254")) {
                            hasIp = true;
                            log.info("Found Candidate: [{}] {} (IP: {})", dev.getName(), dev.getDescription(), ip);
                        }
                    }
                }

                // Prioritize Real Network Adapters with IPs
                if (hasIp && isRealNetwork && !isVirtual && !isLoopback) {
                    return dev; // Found ideal candidate, return immediately
                }

                // Fallback: Keep track of any interface with an IP just in case
                if (hasIp && !isLoopback && bestCandidate == null) {
                    bestCandidate = dev;
                }
            }

            // If no ideal "Wi-Fi/Ethernet" found, use best fallback
            return bestCandidate != null ? bestCandidate : allDevs.get(0);

        } catch (PcapNativeException e) {
            log.error("Error listing network interfaces", e);
            return null;
        }
    }

    // --- ANALYSIS LOOP ---
    private void analysisLoop() {
        while (capturing) {
            try {
                Packet packet = packetQueue.poll(1, TimeUnit.SECONDS);
                if (packet != null) processPacket(packet);
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            catch (Exception e) { }
        }
    }

    private void processPacket(Packet packet) {
        ArpPacket arpPacket = packet.get(ArpPacket.class);
        if (arpPacket != null) return;

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
            if (f.getGeoLocation() == null) {
                f.setGeoLocation(geoIpService.resolve(srcIp));
            }
            return f;
        });

        flowSizeStats.addValue(flow.getBytes());
        if (!detectionQueue.offer(flow)) { /* Drop if busy */ }
    }

    // --- DETECTION LOOP ---
    private void detectionLoop() {
        while (capturing) {
            try {
                FlowRecord flow = detectionQueue.poll(1, TimeUnit.SECONDS);
                if (flow != null) {
                    checkSignatures(flow);
                    checkHeuristics(flow);
                    checkProtocolAnomalies(flow);
                }
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
    }

    private void checkSignatures(FlowRecord flow) {
        Optional<DetectionRule> matchedRule = ruleEngine.evaluate(flow);
        if (matchedRule.isPresent()) {
            DetectionRule rule = matchedRule.get();
            if (flow.getPacketCount() % 50 == 0) {
                publishAlert("RULE MATCH: " + rule.getName(), rule.getDescription(), rule.getSeverity());
                executeAutomatedAction(rule.getAction(), flow.getSrcIp());
            }
        }
    }

    private void checkHeuristics(FlowRecord flow) {
        if (flow.getSynCount() > synFloodThreshold) {
            publishAlert("SYN FLOOD", "High SYN rate ("+flow.getSynCount()+") from " + flow.srcIp, "CRITICAL");
            executeAutomatedAction("BLOCK", flow.getSrcIp());
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
                publishAlert("DNS TUNNELING", "Suspiciously large DNS packet", "HIGH");
            }
        }
    }

    private void executeAutomatedAction(String action, String ip) {
        if (action == null || action.equalsIgnoreCase("ALERT")) return;
        if (action.equalsIgnoreCase("BLOCK")) {
            if (!blockedIps.contains(ip)) {
                blockIp(ip);
                publishAlert("AUTO-BLOCK", "System blocked IP: " + ip, "INFO");
            }
        }
    }

    // --- STATS & HOUSEKEEPING ---
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
                        details.put("metadata", f.getMetadata());
                        forensicLogger.logEvent("FLOW", "FLOW_EXPIRY", "INFO", details);
                    }
                } catch (Exception e) { log.error("Error saving expired flow", e); }
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
                publishAlert("TRAFFIC ANOMALY", "Z-Score: " + String.format("%.2f", zScore), "MEDIUM");
            }
        }

        long currentBandwidth = currentRate * 800 * 8;

        try {
            TrafficStats stats = new TrafficStats(
                    null, new Date(), currentRate, currentBandwidth,
                    flowTable.size(), tcpCount.get(), udpCount.get(), icmpCount.get()
            );
            statsRepository.save(stats);
        } catch (Exception e) { log.error("Error saving stats", e); }

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
        statsMap.put("capturing", capturing);

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
        try { dumper = handle.dumpOpen(LOG_DIR + File.separator + "capture_" + System.currentTimeMillis() + ".pcap"); }
        catch (Exception e) { log.warn("Failed to open dump file: {}", e.getMessage()); }
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

    public Collection<FlowRecord> getActiveFlows() { return flowTable.values(); }
    public void blockIp(String ip) { blockedIps.add(ip); }
    public void unblockIp(String ip) { blockedIps.remove(ip); }
    public Set<String> getBlockedIps() { return blockedIps; }
    public int getSynFloodThreshold() { return synFloodThreshold; }
    public void setSynFloodThreshold(int val) { this.synFloodThreshold = val; }
    public int getPortScanThreshold() { return portScanThreshold; }
    public void setPortScanThreshold(int val) { this.portScanThreshold = val; }
    public double getZScoreThreshold() { return zScoreThreshold; }
    public void setZScoreThreshold(double val) { this.zScoreThreshold = val; }

    public static class FlowRecord {
        private String srcIp; private String dstIp; private String protocol;
        private long packetCount; private long bytes; private int synCount;
        private int maxPayloadSize = 0;
        private Set<Integer> uniquePorts = ConcurrentHashMap.newKeySet();
        private long firstSeen; private long lastSeen;
        private String metadata;
        private GeoIpService.GeoLocation geoLocation;

        public FlowRecord(String s, String d, String p) {
            this.srcIp = s; this.dstIp = d; this.protocol = p;
            this.firstSeen = System.currentTimeMillis(); this.lastSeen = System.currentTimeMillis();
        }
        public void update(long len, boolean isSyn, int port, int payloadSize, String appInfo) {
            this.packetCount++; this.bytes += len; this.lastSeen = System.currentTimeMillis();
            if (isSyn) this.synCount++;
            if (port > 0) this.uniquePorts.add(port);
            if (payloadSize > this.maxPayloadSize) this.maxPayloadSize = payloadSize;
            if (appInfo != null) this.metadata = appInfo;
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
        public String getMetadata() { return metadata; }
        public GeoIpService.GeoLocation getGeoLocation() { return geoLocation; }
        public void setGeoLocation(GeoIpService.GeoLocation g) { this.geoLocation = g; }
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