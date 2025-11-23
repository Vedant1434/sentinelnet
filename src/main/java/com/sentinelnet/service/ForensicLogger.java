package com.sentinelnet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class ForensicLogger {

    private static final String LOG_FILE = "forensic_logs/audit.jsonl";
    private final ObjectMapper objectMapper = new ObjectMapper();

    public synchronized void logEvent(String category, String type, String severity, Map<String, Object> details) {
        try {
            // Ensure directory exists
            new File("forensic_logs").mkdirs();

            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("timestamp", Instant.now().toString());
            logEntry.put("category", category); // e.g., ALERT, FLOW, SYSTEM
            logEntry.put("type", type);         // e.g., SYN_FLOOD, FLOW_EXPIRY
            logEntry.put("severity", severity); // e.g., CRITICAL, INFO
            logEntry.put("details", details);

            String json = objectMapper.writeValueAsString(logEntry);

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
                writer.write(json);
                writer.newLine();
            }
        } catch (IOException e) {
            log.error("Failed to write forensic log", e);
        }
    }

    public File getAuditLogFile() {
        return new File(LOG_FILE);
    }
}