package com.cybertrace.service;

import com.cybertrace.model.SecurityEvent;
import com.cybertrace.model.TimelineEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Service that reconstructs the chronological attack timeline and flags the initial infiltration point.
 */
@Service
public class TimelineService {

    /**
     * Reconstructs chronological forensic attack timeline from evaluated events.
     */
    public List<TimelineEvent> buildTimeline(List<SecurityEvent> events) {
        List<TimelineEvent> timeline = new ArrayList<>();
        if (events == null || events.isEmpty()) return timeline;

        boolean firstSuspiciousFlagged = false;

        for (SecurityEvent event : events) {
            boolean isSuspicious = event.getRiskScore() > 20 || !"NORMAL".equalsIgnoreCase(event.getSeverity());
            boolean isFirst = false;

            if (isSuspicious && !firstSuspiciousFlagged) {
                isFirst = true;
                firstSuspiciousFlagged = true;
            }

            String description = generateDescription(event);

            TimelineEvent tl = new TimelineEvent(
                    event.getTimestamp(),
                    event.getAction(),
                    description,
                    event.getUser(),
                    event.getDevice(),
                    event.getIp(),
                    event.getFile(),
                    event.getRiskScore(),
                    event.getSeverity(),
                    isFirst
            );

            timeline.add(tl);
        }

        return timeline;
    }

    private String generateDescription(SecurityEvent event) {
        String action = (event.getAction() != null) ? event.getAction().toUpperCase() : "";
        String user = event.getUser();
        String ip = event.getIp();
        String file = event.getFile();
        int dataSize = event.getDataSize();

        if (action.contains("LOGIN") && !action.contains("FAIL")) {
            return "User " + user + " logged in from " + ip;
        } else if (action.contains("FAIL")) {
            return "Authentication failure for user " + user + " from IP " + ip;
        } else if (action.contains("FILE") || !file.isEmpty()) {
            return "File access: " + file + " by " + user + " on " + event.getDevice();
        } else if (action.contains("TRANSFER")) {
            return "Data transfer of " + dataSize + " MB outbound to " + ip;
        } else if (action.contains("PRIVILEGE") || action.contains("SUDO") || action.contains("ROOT")) {
            return "Privilege escalation executed on " + event.getDevice();
        } else if (action.contains("LOGOUT")) {
            return "User " + user + " terminated session / logged out";
        }

        return action + " performed by " + user + " from " + ip;
    }
}
