package com.sentinelnet.web;

import com.sentinelnet.core.SentinelNetService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DashboardPushService {

    private final SimpMessagingTemplate messagingTemplate;

    @EventListener
    public void handleAlert(SentinelNetService.AlertEvent event) {
        messagingTemplate.convertAndSend("/topic/alerts", event.getAlert());
    }

    @EventListener
    public void handleStats(SentinelNetService.StatsEvent event) {
        messagingTemplate.convertAndSend("/topic/stats", event.getStats());
    }

    @EventListener
    public void handleFlows(SentinelNetService.FlowsEvent event) {
        messagingTemplate.convertAndSend("/topic/flows", event.getFlows());
    }
}