package com.cybertrace.dto;

/**
 * Deterministic evidence-grounded response returned by the Investigator engine.
 */
public class InvestigatorResponse {
    private String question;
    private String answer;
    private String timestamp;
    private String confidence;

    public InvestigatorResponse() {
        this.timestamp = java.time.Instant.now().toString();
        this.confidence = "HIGH (100% Evidence-Grounded)";
    }

    public InvestigatorResponse(String question, String answer) {
        this.question = question;
        this.answer = answer;
        this.timestamp = java.time.Instant.now().toString();
        this.confidence = "HIGH (100% Evidence-Grounded)";
    }

    public String getQuestion() { return question; }
    public void setQuestion(String question) { this.question = question; }

    public String getAnswer() { return answer; }
    public void setAnswer(String answer) { this.answer = answer; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getConfidence() { return confidence; }
    public void setConfidence(String confidence) { this.confidence = confidence; }
}
