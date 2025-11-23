package com.sentinelnet.web;

import com.sentinelnet.core.SentinelNetService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class SettingsController {
    private final SentinelNetService service;

    @GetMapping("/settings")
    public SettingsDTO getSettings() {
        return new SettingsDTO(service.getSynFloodThreshold(), service.getPortScanThreshold(), service.getZScoreThreshold());
    }

    @PostMapping("/settings")
    public ResponseEntity<String> updateSettings(@RequestBody SettingsDTO dto) {
        service.setSynFloodThreshold(dto.getSynFloodThreshold());
        service.setPortScanThreshold(dto.getPortScanThreshold());
        service.setZScoreThreshold(dto.getZScoreThreshold());
        return ResponseEntity.ok("Settings Updated");
    }

    @PostMapping("/block/{ip}")
    public ResponseEntity<String> blockIp(@PathVariable String ip) {
        service.blockIp(ip);
        return ResponseEntity.ok("IP Blocked: " + ip);
    }

    @PostMapping("/unblock/{ip}")
    public ResponseEntity<String> unblockIp(@PathVariable String ip) {
        service.unblockIp(ip);
        return ResponseEntity.ok("IP Unblocked: " + ip);
    }

    @GetMapping("/blocked")
    public Set<String> getBlockedIps() {
        return service.getBlockedIps();
    }

    @Data @NoArgsConstructor @AllArgsConstructor
    static class SettingsDTO {
        private int synFloodThreshold;
        private int portScanThreshold;
        private double zScoreThreshold;
    }
}