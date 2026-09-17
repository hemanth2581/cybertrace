package com.cybertrace.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class HealthController {

    private final Instant startTime = Instant.now();

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "UP");
        status.put("platform", "CyberTrace AI Digital Forensics");
        status.put("stack", "Java 21 + Spring Boot 3 + HTML5/CSS3/JS");
        status.put("databaseMode", "NONE (Pure Browser LocalStorage)");
        status.put("storageKeys", new String[]{
                "cybertrace_events",
                "cybertrace_anomalies",
                "cybertrace_incidents",
                "cybertrace_evidence",
                "cybertrace_timeline",
                "cybertrace_investigations"
        });
        status.put("startTime", startTime.toString());
        return ResponseEntity.ok(status);
    }
}
