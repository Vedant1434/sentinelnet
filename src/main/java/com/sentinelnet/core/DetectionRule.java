package com.sentinelnet.core;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a signature-based detection rule loaded from JSON.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DetectionRule {
    private String id;
    private String name;
    private String description;
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    // Matching Criteria (If value is -1 or null, it is ignored)
    private String protocol;      // TCP, UDP, ICMP
    private int targetPort = -1;  // e.g., 80, 443

    // Thresholds
    private long minPacketCount = -1;
    private long minBytes = -1;
    private int minSynCount = -1;

    public boolean matches(SentinelNetService.FlowRecord flow) {
        // 1. Check Protocol
        if (protocol != null && !protocol.equalsIgnoreCase(flow.getProtocol())) {
            return false;
        }

        // 2. Check Port (Check both source and dest, usually dest for attacks)
        if (targetPort != -1) {
            boolean portMatch = false;
            for (Integer port : flow.getUniquePorts()) {
                if (port == targetPort) {
                    portMatch = true;
                    break;
                }
            }
            if (!portMatch) return false;
        }

        // 3. Check Thresholds
        if (minPacketCount != -1 && flow.getPacketCount() < minPacketCount) return false;
        if (minBytes != -1 && flow.getBytes() < minBytes) return false;
        if (minSynCount != -1 && flow.getSynCount() < minSynCount) return false;

        return true;
    }
}