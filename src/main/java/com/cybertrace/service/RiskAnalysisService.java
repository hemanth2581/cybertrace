package com.cybertrace.service;

import com.cybertrace.model.SecurityEvent;
import com.cybertrace.util.IpUtils;
import com.cybertrace.util.RiskUtils;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic heuristic risk scoring engine for security telemetry.
 */
@Service
public class RiskAnalysisService {

    /**
     * Evaluates a list of security events and populates riskScore, severity, and reason.
     */
    public List<SecurityEvent> analyzeEvents(List<SecurityEvent> events) {
        if (events == null) return new ArrayList<>();

        for (SecurityEvent event : events) {
            analyzeSingleEvent(event);
        }

        return events;
    }

    /**
     * Evaluates a single security event against rule-based penalty thresholds.
     */
    public SecurityEvent analyzeSingleEvent(SecurityEvent event) {
        int score = 0;
        List<String> reasons = new ArrayList<>();
        int triggers = 0;

        String action = (event.getAction() != null) ? event.getAction().toUpperCase().trim() : "";
        String file = (event.getFile() != null) ? event.getFile().trim() : "";
        String ip = (event.getIp() != null) ? event.getIp().trim() : "";
        int dataSize = event.getDataSize();

        // 1. Failed Login / Brute Force Detection (+20)
        if (action.contains("FAILED_LOGIN") || action.contains("LOGIN_FAILED") || 
            action.contains("AUTH_FAIL") || action.contains("BRUTE_FORCE")) {
            score += 20;
            reasons.add("Authentication failure / failed login detected (+20)");
            triggers++;
        }

        // 2. External IP Address Detection (+20)
        if (IpUtils.isExternalIp(ip)) {
            score += 20;
            reasons.add("External public IP origin: " + ip + " (+20)");
            triggers++;
        }

        // 3. Sensitive File Access Detection (+20)
        if (!file.isEmpty() && RiskUtils.isSensitiveFile(file)) {
            score += 20;
            reasons.add("Sensitive credential/database file access: " + file + " (+20)");
            triggers++;
        }

        // 4. Large Outbound Data Transfer Detection (+15)
        if (dataSize >= 500) {
            score += 15;
            reasons.add("Large outbound data transfer (" + dataSize + " MB) exceeding 500MB threshold (+15)");
            triggers++;
        }

        // 5. Privilege Escalation Detection (+10)
        if (action.contains("PRIVILEGE_ESCALATION") || action.contains("SUDO") || 
            action.contains("ADMIN_ELEVATION") || action.contains("ROOT_ACCESS")) {
            score += 10;
            reasons.add("Privilege escalation attempt detected (+10)");
            triggers++;
        }

        // 6. Compound Multi-Vector Penalty (+7)
        if (triggers >= 3) {
            score += 7;
            reasons.add("Compound multi-vector attack correlation penalty (+7)");
        }

        // Cap at 100
        if (score > 100) {
            score = 100;
        }

        event.setRiskScore(score);
        event.setSeverity(RiskUtils.getSeverityLevel(score));

        if (reasons.isEmpty()) {
            event.setReason("Routine internal enterprise baseline activity");
        } else {
            event.setReason(String.join("; ", reasons));
        }

        return event;
    }
}
