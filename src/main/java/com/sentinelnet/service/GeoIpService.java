package com.sentinelnet.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class GeoIpService {

    private final RestTemplate restTemplate = new RestTemplate();
    // Cache to store IP -> Location data (avoids API rate limits)
    private final Map<String, GeoLocation> cache = new ConcurrentHashMap<>();

    public GeoLocation resolve(String ip) {
        // Skip private IPs
        if (isPrivateIp(ip)) {
            return new GeoLocation("Private Network", "LAN", 0.0, 0.0);
        }

        // Check cache first
        if (cache.containsKey(ip)) {
            return cache.get(ip);
        }

        try {
            // Use ip-api.com (free for non-commercial use, rate limited)
            String url = "http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,lat,lon";
            Map<String, Object> response = restTemplate.getForObject(url, Map.class);

            if (response != null && "success".equals(response.get("status"))) {
                GeoLocation loc = new GeoLocation(
                        (String) response.get("country"),
                        (String) response.get("countryCode"),
                        (Double) response.get("lat"),
                        (Double) response.get("lon")
                );
                cache.put(ip, loc);
                return loc;
            }
        } catch (Exception e) {
            // Silently fail and return unknown
        }

        // Return unknown if failed
        return new GeoLocation("Unknown", "UNK", 0.0, 0.0);
    }

    private boolean isPrivateIp(String ip) {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("127.") || ip.startsWith("172.");
    }

    // DTO for Location Data
    public static class GeoLocation {
        public String country;
        public String countryCode;
        public double lat;
        public double lon;

        public GeoLocation(String c, String cc, double lat, double lon) {
            this.country = c;
            this.countryCode = cc;
            this.lat = lat;
            this.lon = lon;
        }
    }
}