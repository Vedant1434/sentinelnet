package com.sentinelnet.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MapController {

    @GetMapping("/map")
    public String showAttackMap() {
        return "map"; // Serves src/main/resources/templates/map.html
    }
}