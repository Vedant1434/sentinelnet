package com.sentinelnet.web;

import com.sentinelnet.core.SentinelNetService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Collection;

@RestController
@RequestMapping("/api/flows")
@RequiredArgsConstructor
public class FlowController {
    private final SentinelNetService service;

    @GetMapping
    public Collection<SentinelNetService.FlowRecord> getFlows() {
        return service.getActiveFlows();
    }
}