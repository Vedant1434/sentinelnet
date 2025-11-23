package com.sentinelnet.web;

import com.sentinelnet.AlertRepository;
import com.sentinelnet.PersistentAlert;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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

    // NEW: Endpoint to delete all alerts
    @DeleteMapping("/clear")
    public ResponseEntity<String> clearAllAlerts() {
        alertRepository.deleteAll();
        return ResponseEntity.ok("All alerts cleared.");
    }
}