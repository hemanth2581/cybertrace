package com.cybertrace.service;

import com.cybertrace.model.Incident;
import com.cybertrace.model.SecurityEvent;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Service that correlates suspicious events into structured incident response cases.
 */
@Service
public class IncidentService {

    /**
     * Correlates evaluated security events into actionable incident dossiers.
     */
    public List<Incident> generateIncidents(List<SecurityEvent> events) {
        List<Incident> incidents = new ArrayList<>();
        if (events == null || events.isEmpty()) return incidents;

        // Filter suspicious events
        List<SecurityEvent> suspicious = events.stream()
                .filter(e -> e.getRiskScore() > 20 || !"NORMAL".equalsIgnoreCase(e.getSeverity()))
                .toList();

        if (suspicious.isEmpty()) {
            return incidents; // No incidents for normal baseline logs
        }

        // Group by affected user / principal
        Map<String, List<SecurityEvent>> userGroups = new LinkedHashMap<>();
        for (SecurityEvent s : suspicious) {
            userGroups.computeIfAbsent(s.getUser(), k -> new ArrayList<>()).add(s);
        }

        int incIndex = 1;
        for (Map.Entry<String, List<SecurityEvent>> entry : userGroups.entrySet()) {
            String user = entry.getKey();
            List<SecurityEvent> userSuspicious = entry.getValue();

            String incidentId = String.format("INC-%03d", incIndex++);
            
            // Calculate highest severity
            int maxScore = 0;
            String highestSeverity = "MEDIUM";
            String sourceIp = "UNKNOWN";
            boolean hasFailedLogin = false;
            boolean hasSensitiveFile = false;
            boolean hasLargeTransfer = false;
            boolean hasPrivEscalation = false;

            for (SecurityEvent ev : userSuspicious) {
                if (ev.getRiskScore() > maxScore) {
                    maxScore = ev.getRiskScore();
                    highestSeverity = ev.getSeverity();
                }
                if (!"0.0.0.0".equals(ev.getIp()) && !"127.0.0.1".equals(ev.getIp())) {
                    sourceIp = ev.getIp();
                }
                String act = (ev.getAction() != null) ? ev.getAction().toUpperCase() : "";
                if (act.contains("LOGIN") || act.contains("AUTH")) hasFailedLogin = true;
                if (ev.getFile() != null && !ev.getFile().isEmpty()) hasSensitiveFile = true;
                if (ev.getDataSize() >= 500 || act.contains("TRANSFER") || act.contains("EXFIL")) hasLargeTransfer = true;
                if (act.contains("PRIVILEGE") || act.contains("SUDO") || act.contains("ROOT")) hasPrivEscalation = true;
            }

            // Determine incident title
            String title;
            if (hasFailedLogin && (hasSensitiveFile || hasPrivEscalation)) {
                title = "Account Compromise Detected";
            } else if (hasLargeTransfer || (hasSensitiveFile && hasLargeTransfer)) {
                title = "Data Exfiltration Detected";
            } else if (hasPrivEscalation) {
                title = "Unauthorized Privilege Escalation";
            } else {
                title = "Suspicious Host Activity Detected";
            }

            SecurityEvent firstEvt = userSuspicious.get(0);
            String firstDesc = firstEvt.getAction() + " from " + firstEvt.getIp() + " at " + firstEvt.getTimestamp();

            Incident incident = new Incident(
                    incidentId,
                    title,
                    highestSeverity,
                    firstDesc,
                    user,
                    sourceIp,
                    userSuspicious.size(),
                    "OPEN",
                    firstEvt.getTimestamp()
            );

            // Add forensic response recommendations
            List<String> recs = new ArrayList<>();
            recs.add("Immediately revoke active session tokens and reset password for user: " + user);
            recs.add("Enforce firewall block rule on origin source IP: " + sourceIp);
            recs.add("Quarantine host workstation (" + firstEvt.getDevice() + ") for endpoint forensic triage");
            if (hasSensitiveFile || hasLargeTransfer) {
                recs.add("Initiate data loss prevention (DLP) audit on compromised files & databases");
            }
            incident.setRecommendations(recs);

            incidents.add(incident);
        }

        return incidents;
    }
}
