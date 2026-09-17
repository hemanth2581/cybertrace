package com.cybertrace.dto;

import com.cybertrace.model.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Encapsulates the complete digital forensics pipeline analysis response.
 */
public class AnalysisResult {
    private boolean success;
    private String message;
    private List<SecurityEvent> events;
    private List<Anomaly> anomalies;
    private List<Incident> incidents;
    private List<TimelineEvent> timeline;
    private Evidence evidence;
    private Map<String, Object> stats;

    public AnalysisResult() {
        this.success = true;
        this.events = new ArrayList<>();
        this.anomalies = new ArrayList<>();
        this.incidents = new ArrayList<>();
        this.timeline = new ArrayList<>();
        this.evidence = new Evidence();
        this.stats = new HashMap<>();
    }

    public static AnalysisResult error(String message) {
        AnalysisResult res = new AnalysisResult();
        res.setSuccess(false);
        res.setMessage(message);
        return res;
    }

    // Getters and Setters
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public List<SecurityEvent> getEvents() { return events; }
    public void setEvents(List<SecurityEvent> events) { this.events = events; }

    public List<Anomaly> getAnomalies() { return anomalies; }
    public void setAnomalies(List<Anomaly> anomalies) { this.anomalies = anomalies; }

    public List<Incident> getIncidents() { return incidents; }
    public void setIncidents(List<Incident> incidents) { this.incidents = incidents; }

    public List<TimelineEvent> getTimeline() { return timeline; }
    public void setTimeline(List<TimelineEvent> timeline) { this.timeline = timeline; }

    public Evidence getEvidence() { return evidence; }
    public void setEvidence(Evidence evidence) { this.evidence = evidence; }

    public Map<String, Object> getStats() { return stats; }
    public void setStats(Map<String, Object> stats) { this.stats = stats; }
}
