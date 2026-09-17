package com.cybertrace.model;

/**
 * Represents a chronological event in the forensic attack progression.
 */
public class TimelineEvent {
    private String timestamp;
    private String eventType;
    private String description;
    private String user;
    private String device;
    private String ip;
    private String file;
    private int riskScore;
    private String severity;
    private boolean firstSuspicious;

    public TimelineEvent() {}

    public TimelineEvent(String timestamp, String eventType, String description, 
                         String user, String device, String ip, String file, 
                         int riskScore, String severity, boolean firstSuspicious) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.description = description;
        this.user = user;
        this.device = device;
        this.ip = ip;
        this.file = (file != null) ? file : "";
        this.riskScore = riskScore;
        this.severity = severity;
        this.firstSuspicious = firstSuspicious;
    }

    // Getters and Setters
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getDevice() { return device; }
    public void setDevice(String device) { this.device = device; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public boolean isFirstSuspicious() { return firstSuspicious; }
    public void setFirstSuspicious(boolean firstSuspicious) { this.firstSuspicious = firstSuspicious; }
}
