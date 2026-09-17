package com.cybertrace.dto;

import com.cybertrace.model.Evidence;
import com.cybertrace.model.Incident;
import com.cybertrace.model.SecurityEvent;
import java.util.List;

/**
 * Request payload sent to the grounded investigator reasoning engine.
 */
public class InvestigatorRequest {
    private String question;
    private List<SecurityEvent> events;
    private Evidence evidence;
    private List<Incident> incidents;

    public InvestigatorRequest() {}

    public String getQuestion() { return question; }
    public void setQuestion(String question) { this.question = question; }

    public List<SecurityEvent> getEvents() { return events; }
    public void setEvents(List<SecurityEvent> events) { this.events = events; }

    public Evidence getEvidence() { return evidence; }
    public void setEvidence(Evidence evidence) { this.evidence = evidence; }

    public List<Incident> getIncidents() { return incidents; }
    public void setIncidents(List<Incident> incidents) { this.incidents = incidents; }
}
