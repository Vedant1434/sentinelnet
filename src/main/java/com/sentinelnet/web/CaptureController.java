package com.sentinelnet.web;

import com.sentinelnet.core.SentinelNetService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/capture")
@RequiredArgsConstructor
public class CaptureController {

    private final SentinelNetService service;

    @PostMapping("/start")
    public ResponseEntity<String> startCapture() {
        if (service.isCapturing()) {
            return ResponseEntity.badRequest().body("Capture is already running.");
        }
        service.startCapture();
        return ResponseEntity.ok("Capture started.");
    }

    @PostMapping("/stop")
    public ResponseEntity<String> stopCapture() {
        if (!service.isCapturing()) {
            return ResponseEntity.badRequest().body("Capture is not running.");
        }
        service.stopCapture();
        return ResponseEntity.ok("Capture stopped.");
    }

    @PostMapping("/filter")
    public ResponseEntity<String> setFilter(@RequestBody Map<String, String> payload) {
        String filter = payload.get("filter");
        if (filter == null) return ResponseEntity.badRequest().body("Filter cannot be empty");

        service.setBpfFilter(filter);
        return ResponseEntity.ok("BPF Filter set to: " + filter);
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("running", service.isCapturing());
        status.put("filter", service.getCurrentFilter());
        return status;
    }
}