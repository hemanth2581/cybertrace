package com.cybertrace.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a correlated forensic incident case synthesized from suspicious events.
 */
public class Incident {
    private String incidentId;
    private String title;
    private String severity;
    private String firstSuspiciousEvent;
    private String affectedUser;
    private String sourceIP;
    private int suspiciousEventCount;
    private String status;
    private String createdAt;
    private List<String> recommendations;

    public Incident() {
        this.status = "OPEN";
        this.recommendations = new ArrayList<>();
    }

    public Incident(String incidentId, String title, String severity, 
                    String firstSuspiciousEvent, String affectedUser, 
                    String sourceIP, int suspiciousEventCount, 
                    String status, String createdAt) {
        this.incidentId = incidentId;
        this.title = title;
        this.severity = severity;
        this.firstSuspiciousEvent = firstSuspiciousEvent;
        this.affectedUser = affectedUser;
        this.sourceIP = sourceIP;
        this.suspiciousEventCount = suspiciousEventCount;
        this.status = status;
        this.createdAt = createdAt;
        this.recommendations = new ArrayList<>();
    }

    // Getters and Setters
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getFirstSuspiciousEvent() { return firstSuspiciousEvent; }
    public void setFirstSuspiciousEvent(String firstSuspiciousEvent) { this.firstSuspiciousEvent = firstSuspiciousEvent; }

    public String getAffectedUser() { return affectedUser; }
    public void setAffectedUser(String affectedUser) { this.affectedUser = affectedUser; }

    public String getSourceIP() { return sourceIP; }
    public void setSourceIP(String sourceIP) { this.sourceIP = sourceIP; }

    public int getSuspiciousEventCount() { return suspiciousEventCount; }
    public void setSuspiciousEventCount(int suspiciousEventCount) { this.suspiciousEventCount = suspiciousEventCount; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
}
