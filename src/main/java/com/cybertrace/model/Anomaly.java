package com.cybertrace.model;

/**
 * Represents a flagged suspicious activity or anomalous event.
 */
public class Anomaly {
    private String id;
    private String eventId;
    private String timestamp;
    private String user;
    private String ip;
    private String action;
    private int riskScore;
    private String severity;
    private String reason;
    private String detectedAt;

    public Anomaly() {}

    public Anomaly(String id, String eventId, String timestamp, String user, 
                   String ip, String action, int riskScore, String severity, 
                   String reason, String detectedAt) {
        this.id = id;
        this.eventId = eventId;
        this.timestamp = timestamp;
        this.user = user;
        this.ip = ip;
        this.action = action;
        this.riskScore = riskScore;
        this.severity = severity;
        this.reason = reason;
        this.detectedAt = detectedAt;
    }

    public static Anomaly fromSecurityEvent(SecurityEvent event, String anomalyId) {
        return new Anomaly(
            anomalyId,
            event.getId(),
            event.getTimestamp(),
            event.getUser(),
            event.getIp(),
            event.getAction(),
            event.getRiskScore(),
            event.getSeverity(),
            event.getReason(),
            java.time.Instant.now().toString()
        );
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getDetectedAt() { return detectedAt; }
    public void setDetectedAt(String detectedAt) { this.detectedAt = detectedAt; }
}
