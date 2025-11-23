package com.sentinelnet.service;

import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DpiService {

    private static final Pattern HTTP_METHOD = Pattern.compile("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ");
    private static final Pattern HTTP_HOST = Pattern.compile("Host: ([\\w.-]+)");
    private static final Pattern USER_AGENT = Pattern.compile("User-Agent: (.*?)(\\r\\n|$)");

    /**
     * Inspects payload to determine Layer 7 Application info.
     * @return String description (e.g., "HTTP: google.com", "SSH-2.0") or null.
     */
    public String inspect(byte[] payload, String protocol, int port) {
        if (payload == null || payload.length == 0) return null;

        // Convert to string for text-based protocols
        String text = new String(payload, StandardCharsets.UTF_8);

        // 1. HTTP Inspection
        Matcher methodMatcher = HTTP_METHOD.matcher(text);
        if (methodMatcher.find()) {
            String method = methodMatcher.group(1);
            String host = "unknown";
            Matcher hostMatcher = HTTP_HOST.matcher(text);
            if (hostMatcher.find()) host = hostMatcher.group(1);
            return "HTTP: " + method + " " + host;
        }

        // 2. TLS/SSL Inspection (Client Hello)
        // Content Type: 22 (Handshake), Version: 03 01/02/03
        if (payload.length > 5 && payload[0] == 0x16 && payload[1] == 0x03) {
            return "TLS/SSL Handshake";
            // Full SNI parsing requires complex byte walking, keeping it simple for stability.
        }

        // 3. SSH Inspection
        if (text.startsWith("SSH-")) {
            return "SSH: " + text.trim();
        }

        // 4. FTP Inspection
        if (port == 21 && (text.startsWith("USER ") || text.startsWith("220 "))) {
            return "FTP Cmd";
        }

        // 5. DNS (Heuristic for non-parsed DNS)
        if (port == 53 && payload.length > 12) {
            return "DNS Query";
        }

        return null;
    }
}