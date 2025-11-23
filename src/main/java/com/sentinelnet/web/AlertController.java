package com.sentinelnet.web;

import com.sentinelnet.AlertRepository;
import com.sentinelnet.PersistentAlert;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
public class AlertController {
    private final AlertRepository alertRepository;

    @GetMapping("/history")
    public List<PersistentAlert> getAlertHistory() {
        return alertRepository.findTop50ByOrderByIdDesc();
    }

    @DeleteMapping("/clear")
    public ResponseEntity<String> clearAllAlerts() {
        alertRepository.deleteAll();
        return ResponseEntity.ok("All alerts cleared.");
    }

    // NEW: Export to CSV
    @GetMapping("/export/csv")
    public ResponseEntity<Resource> exportAlertsToCsv() {
        List<PersistentAlert> alerts = alertRepository.findAll();
        StringBuilder csv = new StringBuilder();
        csv.append("ID,Type,Severity,Description,Timestamp\n");

        for (PersistentAlert alert : alerts) {
            csv.append(alert.getId()).append(",")
                    .append(escapeCsv(alert.getType())).append(",")
                    .append(escapeCsv(alert.getSeverity())).append(",")
                    .append(escapeCsv(alert.getDescription())).append(",")
                    .append(escapeCsv(alert.getTimestamp())).append("\n");
        }

        ByteArrayResource resource = new ByteArrayResource(csv.toString().getBytes(StandardCharsets.UTF_8));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=alerts_export.csv")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(resource);
    }

    private String escapeCsv(String data) {
        if (data == null) return "";
        return "\"" + data.replace("\"", "\"\"") + "\"";
    }
}