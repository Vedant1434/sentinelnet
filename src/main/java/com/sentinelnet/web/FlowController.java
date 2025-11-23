package com.sentinelnet.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelnet.core.SentinelNetService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Collection;

@RestController
@RequestMapping("/api/flows")
@RequiredArgsConstructor
public class FlowController {
    private final SentinelNetService service;
    private final ObjectMapper objectMapper;

    @GetMapping
    public Collection<SentinelNetService.FlowRecord> getFlows() {
        return service.getActiveFlows();
    }

    // NEW: Export Active Flows to JSON
    @GetMapping("/export/json")
    public ResponseEntity<Resource> exportFlowsToJson() {
        try {
            Collection<SentinelNetService.FlowRecord> flows = service.getActiveFlows();
            String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(flows);
            ByteArrayResource resource = new ByteArrayResource(json.getBytes(StandardCharsets.UTF_8));

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=active_flows.json")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(resource);
        } catch (JsonProcessingException e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}