package com.sentinelnet;

import com.sentinelnet.core.SentinelNetService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.socket.config.annotation.*;

import java.io.File;
import java.util.Collection;
import java.util.List;

/**
 * UPDATED: Added Forensics and Settings REST Controllers.
 */
@SpringBootApplication
@EnableScheduling
public class SentinelNetApplication {
    public static void main(String[] args) {
        SpringApplication.run(SentinelNetApplication.class, args);
    }
}

// --- WebSocket Configuration ---
@org.springframework.context.annotation.Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic");
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws-sentinel").withSockJS();
    }
}

// --- DTOs ---
@Data @NoArgsConstructor @AllArgsConstructor
class SettingsDTO {
    private int synFloodThreshold;
    private int portScanThreshold;
    private double zScoreThreshold;
}

// --- Controllers ---
@Controller
class WebController {
    @GetMapping("/")
    public String dashboard() {
        return "dashboard";
    }
}

@RestController
@AllArgsConstructor
class ApiController {
    private final SentinelNetService service;
    private final AlertRepository alertRepository;

    @GetMapping("/api/flows")
    public Collection<SentinelNetService.FlowRecord> getFlows() {
        return service.getActiveFlows();
    }

    @GetMapping("/api/alerts/history")
    public List<PersistentAlert> getAlertHistory() {
        return alertRepository.findTop50ByOrderByIdDesc();
    }

    // --- Settings Endpoints ---
    @GetMapping("/api/settings")
    public SettingsDTO getSettings() {
        return new SettingsDTO(
                service.getSynFloodThreshold(),
                service.getPortScanThreshold(),
                service.getZScoreThreshold()
        );
    }

    @PostMapping("/api/settings")
    public ResponseEntity<String> updateSettings(@RequestBody SettingsDTO dto) {
        service.setSynFloodThreshold(dto.getSynFloodThreshold());
        service.setPortScanThreshold(dto.getPortScanThreshold());
        service.setZScoreThreshold(dto.getZScoreThreshold());
        return ResponseEntity.ok("Settings Updated");
    }

    // --- Forensics Endpoints ---
    @GetMapping("/api/forensics")
    public List<String> listForensicFiles() {
        return service.listForensicFiles();
    }

    @GetMapping("/api/forensics/download/{filename}")
    public ResponseEntity<Resource> downloadFile(@PathVariable String filename) {
        File file = service.getForensicFile(filename);
        if (file == null || !file.exists()) return ResponseEntity.notFound().build();

        Resource resource = new FileSystemResource(file);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
                .body(resource);
    }
}

// --- Event Listener ---
@Controller
@AllArgsConstructor
class DashboardPushService {
    private final SimpMessagingTemplate messagingTemplate;

    @EventListener
    public void handleAlert(SentinelNetService.AlertEvent event) {
        messagingTemplate.convertAndSend("/topic/alerts", event.getAlert());
    }

    @EventListener
    public void handleStats(SentinelNetService.StatsEvent event) {
        messagingTemplate.convertAndSend("/topic/stats", event.getStats());
    }
}