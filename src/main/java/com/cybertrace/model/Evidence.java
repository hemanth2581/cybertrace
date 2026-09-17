package com.cybertrace.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents the correlated entity chain:
 * USER -> DEVICE -> IP -> FILE -> DATA TRANSFER
 */
public class Evidence {
    private String user;
    private String device;
    private String ip;
    private String file;
    private String dataTransfer;
    private List<String> suspiciousNodes;

    public Evidence() {
        this.user = "N/A";
        this.device = "N/A";
        this.ip = "N/A";
        this.file = "None";
        this.dataTransfer = "0 MB";
        this.suspiciousNodes = new ArrayList<>();
    }

    public Evidence(String user, String device, String ip, String file, 
                    String dataTransfer, List<String> suspiciousNodes) {
        this.user = (user != null && !user.isEmpty()) ? user : "N/A";
        this.device = (device != null && !device.isEmpty()) ? device : "N/A";
        this.ip = (ip != null && !ip.isEmpty()) ? ip : "N/A";
        this.file = (file != null && !file.isEmpty()) ? file : "None";
        this.dataTransfer = (dataTransfer != null) ? dataTransfer : "0 MB";
        this.suspiciousNodes = (suspiciousNodes != null) ? suspiciousNodes : new ArrayList<>();
    }

    // Getters and Setters
    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }

    public String getDevice() { return device; }
    public void setDevice(String device) { this.device = device; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }

    public String getDataTransfer() { return dataTransfer; }
    public void setDataTransfer(String dataTransfer) { this.dataTransfer = dataTransfer; }

    public List<String> getSuspiciousNodes() { return suspiciousNodes; }
    public void setSuspiciousNodes(List<String> suspiciousNodes) { this.suspiciousNodes = suspiciousNodes; }
}
