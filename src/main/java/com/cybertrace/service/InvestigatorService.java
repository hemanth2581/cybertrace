package com.cybertrace.service;

import com.cybertrace.dto.InvestigatorRequest;
import com.cybertrace.dto.InvestigatorResponse;
import com.cybertrace.model.Evidence;
import com.cybertrace.model.Incident;
import com.cybertrace.model.SecurityEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic, 100% evidence-grounded AI Investigator reasoning engine.
 * Never invents facts or hallucinates without verifiable telemetry support.
 */
@Service
public class InvestigatorService {

    public InvestigatorResponse answerQuestion(InvestigatorRequest req) {
        if (req == null || req.getQuestion() == null || req.getQuestion().trim().isEmpty()) {
            return new InvestigatorResponse("", "Please provide a valid forensic investigation question.");
        }

        String q = req.getQuestion().toLowerCase().trim();
        List<SecurityEvent> events = (req.getEvents() != null) ? req.getEvents() : new ArrayList<>();
        Evidence evidence = (req.getEvidence() != null) ? req.getEvidence() : new Evidence();
        List<Incident> incidents = (req.getIncidents() != null) ? req.getIncidents() : new ArrayList<>();

        if (events.isEmpty() && incidents.isEmpty()) {
            return new InvestigatorResponse(
                    req.getQuestion(),
                    "No security telemetry or evidence is currently loaded in the investigation workspace. Please upload a CSV log first."
            );
        }

        List<SecurityEvent> suspicious = events.stream()
                .filter(e -> e.getRiskScore() > 20 || !"NORMAL".equalsIgnoreCase(e.getSeverity()))
                .toList();

        Incident primaryIncident = !incidents.isEmpty() ? incidents.get(0) : null;

        // 1. "What happened?" / "summary"
        if (q.contains("what happened") || q.contains("summary") || q.contains("explain") || q.contains("overview")) {
            if (suspicious.isEmpty()) {
                return new InvestigatorResponse(
                        req.getQuestion(),
                        "Audit logs indicate normal operational baseline activity. No unauthorized anomalies or security incidents were detected."
                );
            }
            StringBuilder sb = new StringBuilder();
            sb.append("User ").append(evidence.getUser()).append(" was targeted in a security incident (");
            sb.append(primaryIncident != null ? primaryIncident.getTitle() : "Suspicious Activity").append("). ");
            
            List<String> actions = new ArrayList<>();
            for (SecurityEvent s : suspicious) {
                if (!actions.contains(s.getAction())) actions.add(s.getAction());
            }
            sb.append("The sequence of events involved ").append(String.join(", ", actions)).append(" originating from IP ");
            sb.append(evidence.getIp()).append(".");
            if (!"None".equals(evidence.getFile())) {
                sb.append(" Sensitive file '").append(evidence.getFile()).append("' was accessed.");
            }
            if (!"0 MB".equals(evidence.getDataTransfer())) {
                sb.append(" An outbound transfer of ").append(evidence.getDataTransfer()).append(" was recorded.");
            }
            return new InvestigatorResponse(req.getQuestion(), sb.toString());
        }

        // 2. "Who was involved?" / "user" / "identity"
        if (q.contains("who") || q.contains("involved") || q.contains("user") || q.contains("victim") || q.contains("account")) {
            if (!"N/A".equals(evidence.getUser())) {
                return new InvestigatorResponse(
                        req.getQuestion(),
                        "The primary user identity involved in this incident is " + evidence.getUser() + " on device " + evidence.getDevice() + "."
                );
            }
            return new InvestigatorResponse(req.getQuestion(), "This information was not found in the available evidence.");
        }

        // 3. "What was the first suspicious event?" / "initial access"
        if (q.contains("first") || q.contains("initial") || q.contains("started") || q.contains("beginning")) {
            if (!suspicious.isEmpty()) {
                SecurityEvent first = suspicious.get(0);
                return new InvestigatorResponse(
                        req.getQuestion(),
                        "The first suspicious event was '" + first.getAction() + "' detected at " + 
                        first.getTimestamp() + " originating from IP " + first.getIp() + " (Risk Score: " + first.getRiskScore() + "/100)."
                );
            }
            return new InvestigatorResponse(req.getQuestion(), "No suspicious events were recorded in the current dataset.");
        }

        // 4. "Which IP was involved?" / "source ip"
        if (q.contains("ip") || q.contains("address") || q.contains("origin") || q.contains("network")) {
            if (!"N/A".equals(evidence.getIp()) && !"0.0.0.0".equals(evidence.getIp())) {
                return new InvestigatorResponse(
                        req.getQuestion(),
                        "The primary source IP address identified during the investigation is " + evidence.getIp() + "."
                );
            }
            return new InvestigatorResponse(req.getQuestion(), "This information was not found in the available evidence.");
        }

        // 5. "Which file was accessed?" / "file"
        if (q.contains("file") || q.contains("document") || q.contains("credential") || q.contains("database")) {
            if (!"None".equals(evidence.getFile()) && !evidence.getFile().isEmpty()) {
                return new InvestigatorResponse(
                        req.getQuestion(),
                        "The file accessed during the incident was '" + evidence.getFile() + "'."
                );
            }
            return new InvestigatorResponse(req.getQuestion(), "No file access was recorded in the available evidence.");
        }

        // 6. "How much data was transferred?" / "transfer" / "exfiltration"
        if (q.contains("data") || q.contains("transfer") || q.contains("bytes") || q.contains("megabytes") || q.contains("mb")) {
            return new InvestigatorResponse(
                    req.getQuestion(),
                    "Total outbound data volume recorded in this investigation is " + evidence.getDataTransfer() + "."
            );
        }

        // 7. "Why was this suspicious?" / "reason" / "threat reason"
        if (q.contains("why") || q.contains("suspicious") || q.contains("reason") || q.contains("flagged")) {
            if (!suspicious.isEmpty()) {
                StringBuilder sb = new StringBuilder("The activity was flagged due to the following detected anomalies: ");
                List<String> reasons = new ArrayList<>();
                for (SecurityEvent s : suspicious) {
                    if (!reasons.contains(s.getReason())) reasons.add(s.getReason());
                }
                sb.append(String.join(" | ", reasons));
                return new InvestigatorResponse(req.getQuestion(), sb.toString());
            }
            return new InvestigatorResponse(req.getQuestion(), "The evaluated events did not exhibit any suspicious or anomalous characteristics.");
        }

        // 8. "How many suspicious events were detected?" / "count" / "number"
        if (q.contains("how many") || q.contains("count") || q.contains("number of")) {
            return new InvestigatorResponse(
                    req.getQuestion(),
                    "A total of " + suspicious.size() + " suspicious event(s) were flagged out of " + events.size() + " total evaluated logs."
            );
        }

        // 9. "What is the threat level?" / "severity" / "risk"
        if (q.contains("threat level") || q.contains("severity") || q.contains("risk level") || q.contains("level")) {
            if (primaryIncident != null) {
                return new InvestigatorResponse(
                        req.getQuestion(),
                        "The overall incident threat level is " + primaryIncident.getSeverity() + " (" + primaryIncident.getTitle() + ")."
                );
            }
            return new InvestigatorResponse(req.getQuestion(), "Threat level is NORMAL (Score: 0/100). System is secure.");
        }

        // Fallback: ground check in evidence
        return new InvestigatorResponse(
                req.getQuestion(),
                "This information was not found in the available evidence."
        );
    }
}
