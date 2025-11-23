package com.sentinelnet.service;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Service
public class ForensicsService {

    private static final String LOG_DIR = "forensic_logs";

    public List<String> listForensicFiles() {
        File dir = new File(LOG_DIR);
        if (!dir.exists()) return Collections.emptyList();
        String[] f = dir.list((d, name) -> name.endsWith(".pcap"));
        Arrays.sort(f, Collections.reverseOrder());
        return f != null ? Arrays.asList(f) : Collections.emptyList();
    }

    public Resource getForensicFile(String filename) {
        if (filename.contains("..") || !filename.endsWith(".pcap")) return null;
        File file = new File(LOG_DIR, filename);
        if (!file.exists()) return null;
        return new FileSystemResource(file);
    }
}