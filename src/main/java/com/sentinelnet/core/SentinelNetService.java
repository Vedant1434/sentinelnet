// ... existing imports ...
package com.sentinelnet.core;

import com.sentinelnet.PersistentAlert;
import com.sentinelnet.AlertRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import java.io.File;
import java.net.Inet4Address;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * UPDATED: Added Active Defense (IP Blocking) capabilities.
 */
@Service
@Slf4j
public class SentinelNetService {

    private final ApplicationEventPublisher eventPublisher;
    private final AlertRepository alertRepository;

    private PcapHandle handle;
    private PcapDumper dumper;
    private final ConcurrentHashMap<String, FlowRecord> flowTable = new ConcurrentHashMap<>();
    private final BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>(10000);
    private final ExecutorService processorPool = Executors.newSingleThreadExecutor();

    // Active Defense: Blacklisted IPs
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();

    private static final String LOG_DIR = "forensic_logs";

    // Statistics
    private final DescriptiveStatistics packetRateStats = new DescriptiveStatistics(100);
    private final AtomicLong currentPacketCount = new AtomicLong(0);
    private final AtomicLong tcpCount = new AtomicLong(0);
    private final AtomicLong udpCount = new AtomicLong(0);
    private final AtomicLong icmpCount = new AtomicLong(0);

    private int synFloodThreshold = 50;
    private int portScanThreshold = 20;
    private double zScoreThreshold = 3.0;

    public SentinelNetService(ApplicationEventPublisher eventPublisher, AlertRepository alertRepository) {
        this.eventPublisher = eventPublisher;
        this.alertRepository = alertRepository;
    }

    // --- Blocking Management ---
    public void blockIp(String ip) {
        blockedIps.add(ip);
        publishAlert("MANUAL BLOCK", "Administrator blocked IP: " + ip, "HIGH");
        log.info("IP Blocked: {}", ip);
    }

    public void unblockIp(String ip) {
        blockedIps.remove(ip);
        log.info("IP Unblocked: {}", ip);
    }

    public Set<String> getBlockedIps() {
        return blockedIps;
    }

    // --- Getters/Setters ---
    public int getSynFloodThreshold() { return synFloodThreshold; }
    public void setSynFloodThreshold(int val) { this.synFloodThreshold = val; }
    public int getPortScanThreshold() { return portScanThreshold; }
    public void setPortScanThreshold(int val) { this.portScanThreshold = val; }
    public double getZScoreThreshold() { return zScoreThreshold; }
    public void setZScoreThreshold(double val) { this.zScoreThreshold = val; }

    // --- Forensics ---
    public List<String> listForensicFiles() {
        File dir = new File(LOG_DIR);
        if (!dir.exists()) dir.mkdirs();
        File[] files = dir.listFiles((d, name) -> name.endsWith(".pcap"));
        if (files == null) return Collections.emptyList();
        List<String> names = new ArrayList<>();
        for (File f : files) names.add(f.getName());
        names.sort(Collections.reverseOrder());
        return names;
    }

    public File getForensicFile(String filename) {
        if (filename.contains("..") || !filename.endsWith(".pcap")) return null;
        return new File(LOG_DIR, filename);
    }

    @PostConstruct
    public void startCapture() {
        new Thread(this::captureLoop, "Pcap-Capture-Thread").start();
        processorPool.submit(this::processQueue);
    }

    private void captureLoop() {
        try {
            PcapNetworkInterface nif = autoSelectInterface();
            if (nif == null) {
                log.error("CRITICAL: No active network interface found.");
                return;
            }
            log.info("CAPTURING ON: {} ({})", nif.getDescription(), nif.getName());

            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            File logDir = new File(LOG_DIR);
            if (!logDir.exists()) logDir.mkdirs();

            try {
                dumper = handle.dumpOpen(LOG_DIR + File.separator + "forensics_" + System.currentTimeMillis() + ".pcap");
            } catch (Exception e) {
                log.warn("Forensics disabled: {}", e.getMessage());
            }

            handle.loop(-1, (PacketListener) packet -> {
                packetQueue.offer(packet);
                currentPacketCount.incrementAndGet();
                try {
                    if (dumper != null && dumper.isOpen()) {
                        dumper.dump(packet, handle.getTimestamp());
                    }
                } catch (NotOpenException e) { }
            });
        } catch (Throwable e) {
            log.error("Capture Loop Error: {}", e.getMessage());
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
                        if (!ip.equals("0.0.0.0") && !ip.equals("127.0.0.1") && !ip.startsWith("169.254")) {
                            return dev;
                        }
                    }
                }
            }
            if (!allDevs.isEmpty()) return allDevs.get(0);
        } catch (Exception e) { }
        return null;
    }

    private void processQueue() {
        while (true) {
            try {
                Packet packet = packetQueue.take();
                analyzePacket(packet);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) { }
        }
    }

    private void analyzePacket(Packet packet) {
        try {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            if (ipV4Packet == null) return;

            String srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();
            String protocol = ipV4Packet.getHeader().getProtocol().name();

            // --- BLOCKING CHECK ---
            if (blockedIps.contains(srcIp)) {
                if (currentPacketCount.get() % 50 == 0) {
                    log.info("Blocked packet dropped from: " + srcIp);
                }
                return; // Drop processing
            }

            if (protocol.equalsIgnoreCase("TCP")) tcpCount.incrementAndGet();
            else if (protocol.equalsIgnoreCase("UDP")) udpCount.incrementAndGet();
            else if (protocol.equalsIgnoreCase("ICMP")) icmpCount.incrementAndGet();

            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            int tempDestPort = 0;
            boolean tempIsSyn = false;

            if (tcpPacket != null) {
                tempDestPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                tempIsSyn = tcpPacket.getHeader().getSyn();
            }

            final int destPort = tempDestPort;
            final boolean isSyn = tempIsSyn;

            String flowKey = srcIp + "-" + dstIp + "-" + protocol;
            flowTable.compute(flowKey, (k, flow) -> {
                if (flow == null) flow = new FlowRecord(srcIp, dstIp, protocol);
                flow.update(packet.length(), isSyn, destPort);
                return flow;
            });

            checkRules(srcIp, dstIp, isSyn, destPort);
        } catch (Exception e) { }
    }

    private void checkRules(String srcIp, String dstIp, boolean isSyn, int destPort) {
        FlowRecord flow = flowTable.get(srcIp + "-" + dstIp + "-TCP");
        if (flow != null) {
            if (flow.getSynCount() > synFloodThreshold && flow.getPacketCount() > 100) {
                publishAlert("SYN FLOOD", "High SYN rate from " + srcIp, "CRITICAL");
                flow.setSynCount(0);
            }
            if (flow.getUniquePorts().size() > portScanThreshold) {
                publishAlert("PORT SCAN", "Scanning detected from " + srcIp, "HIGH");
                flow.getUniquePorts().clear();
            }
        }
    }

    @Scheduled(fixedRate = 1000)
    public void calculateMetrics() {
        long currentRate = currentPacketCount.getAndSet(0);
        packetRateStats.addValue(currentRate);

        double zScore = 0;
        if (packetRateStats.getStandardDeviation() > 0) {
            zScore = (currentRate - packetRateStats.getMean()) / packetRateStats.getStandardDeviation();
            if (Math.abs(zScore) > zScoreThreshold) {
                publishAlert("TRAFFIC ANOMALY", "Z-Score: " + String.format("%.2f", zScore), "MEDIUM");
            }
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("pps", currentRate);
        stats.put("activeFlows", flowTable.size());
        stats.put("bandwidth", currentRate * 64 * 8);
        stats.put("tcp", tcpCount.get());
        stats.put("udp", udpCount.get());
        stats.put("icmp", icmpCount.get());

        eventPublisher.publishEvent(new StatsEvent(this, stats));
    }

    @Scheduled(fixedRate = 5000)
    public void cleanupFlows() {
        long now = System.currentTimeMillis();
        flowTable.entrySet().removeIf(entry -> (now - entry.getValue().getLastSeen()) > 10000);
    }

    public Collection<FlowRecord> getActiveFlows() { return flowTable.values(); }

    private void publishAlert(String type, String message, String severity) {
        log.warn("ALERT [{}]: {}", severity, message);
        try {
            PersistentAlert dbAlert = new PersistentAlert(null, type, message, severity, new Date().toString());
            alertRepository.save(dbAlert);
            Alert alert = new Alert(type, message, severity, new Date());
            eventPublisher.publishEvent(new AlertEvent(this, alert));
        } catch (Exception e) { }
    }

    @PreDestroy
    public void stop() {
        if (dumper != null && dumper.isOpen()) dumper.close();
        if (handle != null && handle.isOpen()) handle.close();
    }

    public static class FlowRecord {
        private String srcIp; private String dstIp; private String protocol;
        private long packetCount; private long bytes; private int synCount;
        private Set<Integer> uniquePorts = new HashSet<>(); private long lastSeen;

        public FlowRecord(String s, String d, String p) {
            this.srcIp = s; this.dstIp = d; this.protocol = p; this.lastSeen = System.currentTimeMillis();
        }
        public void update(int len, boolean isSyn, int port) {
            this.packetCount++; this.bytes += len; this.lastSeen = System.currentTimeMillis();
            if (isSyn) this.synCount++;
            if (port > 0) this.uniquePorts.add(port);
        }

        public long getPacketCount() { return packetCount; }

        // ADDED: Getter for Bytes so it is serialized to JSON
        public long getBytes() { return bytes; }

        public int getSynCount() { return synCount; }
        public void setSynCount(int s) { this.synCount = s; }
        public Set<Integer> getUniquePorts() { return uniquePorts; }
        public long getLastSeen() { return lastSeen; }
        public String getSrcIp() { return srcIp; }
        public String getDstIp() { return dstIp; }
        public String getProtocol() { return protocol; }
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

    public static class AlertEvent extends org.springframework.context.ApplicationEvent {
        private final Alert alert;
        public AlertEvent(Object source, Alert alert) { super(source); this.alert = alert; }
        public Alert getAlert() { return alert; }
    }

    public static class StatsEvent extends org.springframework.context.ApplicationEvent {
        private final Map<String, Object> stats;
        public StatsEvent(Object source, Map<String, Object> stats) { super(source); this.stats = stats; }
        public Map<String, Object> getStats() { return stats; }
    }
}