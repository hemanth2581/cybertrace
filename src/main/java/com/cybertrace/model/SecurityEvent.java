package com.cybertrace.model;

/**
 * Represents a normalized security event parsed from raw audit logs.
 */
public class SecurityEvent {
    private String id;
    private String timestamp;
    private String user;
    private String device;
    private String ip;
    private String action;
    private String file;
    private int dataSize;
    private int riskScore;
    private String severity; // NORMAL, LOW, MEDIUM, HIGH, CRITICAL
    private String reason;

    public SecurityEvent() {
        this.file = "";
        this.dataSize = 0;
        this.riskScore = 0;
        this.severity = "NORMAL";
        this.reason = "Baseline routine activity";
    }

    public SecurityEvent(String id, String timestamp, String user, String device, 
                         String ip, String action, String file, int dataSize) {
        this.id = id;
        this.timestamp = timestamp;
        this.user = user;
        this.device = device;
        this.ip = ip;
        this.action = action;
        this.file = (file != null) ? file : "";
        this.dataSize = dataSize;
        this.riskScore = 0;
        this.severity = "NORMAL";
        this.reason = "Baseline routine activity";
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getDevice() { return device; }
    public void setDevice(String device) { this.device = device; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }

    public int getDataSize() { return dataSize; }
    public void setDataSize(int dataSize) { this.dataSize = dataSize; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}
