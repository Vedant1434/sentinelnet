package com.sentinelnet.web;

import com.sentinelnet.AlertRepository;
import com.sentinelnet.PersistentAlert;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
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
}