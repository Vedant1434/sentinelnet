package com.sentinelnet.core;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class RuleEngine {

    private final List<DetectionRule> activeRules = new ArrayList<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    public void loadRules() {
        try {
            ClassPathResource resource = new ClassPathResource("rules.json");
            if (resource.exists()) {
                try (InputStream is = resource.getInputStream()) {
                    List<DetectionRule> rules = objectMapper.readValue(is, new TypeReference<List<DetectionRule>>() {});
                    activeRules.clear();
                    activeRules.addAll(rules);
                    log.info("Loaded {} detection rules from rules.json", activeRules.size());
                }
            } else {
                log.warn("rules.json not found in resources. Rule engine will be empty.");
            }
        } catch (Exception e) {
            log.error("Failed to load detection rules", e);
        }
    }

    /**
     * Evaluates a network flow against all loaded rules.
     * @return Optional containing the matched rule, or empty if no match.
     */
    public Optional<DetectionRule> evaluate(SentinelNetService.FlowRecord flow) {
        for (DetectionRule rule : activeRules) {
            if (rule.matches(flow)) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }

    public List<DetectionRule> getRules() {
        return activeRules;
    }
}