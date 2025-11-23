package com.sentinelnet.web;

import com.sentinelnet.service.ForensicLogger;
import com.sentinelnet.service.ForensicsService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/forensics")
@RequiredArgsConstructor
public class ForensicsController {
    private final ForensicsService forensicsService;
    private final ForensicLogger forensicLogger;

    @GetMapping
    public List<String> listForensicFiles() {
        return forensicsService.listForensicFiles();
    }

    @GetMapping("/download/{filename}")
    public ResponseEntity<Resource> downloadFile(@PathVariable String filename) {
        Resource resource = forensicsService.getForensicFile(filename);
        if (resource == null) return ResponseEntity.notFound().build();

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .body(resource);
    }

    // NEW: Download the Audit Log
    @GetMapping("/audit-log")
    public ResponseEntity<Resource> downloadAuditLog() {
        Resource resource = new FileSystemResource(forensicLogger.getAuditLogFile());
        if (!resource.exists()) return ResponseEntity.notFound().build();

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"audit.jsonl\"")
                .body(resource);
    }
}