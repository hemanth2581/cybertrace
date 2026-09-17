package com.cybertrace.controller;

import com.cybertrace.dto.AnalysisResult;
import com.cybertrace.model.*;
import com.cybertrace.service.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST Controller for direct JSON event telemetry analysis.
 */
@RestController
@RequestMapping("/api/analyze")
@CrossOrigin(origins = "*")
public class AnalysisController {

    private final RiskAnalysisService riskService;
    private final AnomalyDetectionService anomalyService;
    private final IncidentService incidentService;
    private final TimelineService timelineService;
    private final EvidenceService evidenceService;

    public AnalysisController(RiskAnalysisService riskService,
                              AnomalyDetectionService anomalyService,
                              IncidentService incidentService,
                              TimelineService timelineService,
                              EvidenceService evidenceService) {
        this.riskService = riskService;
        this.anomalyService = anomalyService;
        this.incidentService = incidentService;
        this.timelineService = timelineService;
        this.evidenceService = evidenceService;
    }

    @PostMapping
    public ResponseEntity<AnalysisResult> analyzeJsonEvents(@RequestBody List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return ResponseEntity.badRequest().body(AnalysisResult.error("No security events provided in payload."));
        }

        List<SecurityEvent> evaluatedEvents = riskService.analyzeEvents(events);
        List<Anomaly> anomalies = anomalyService.detectAnomalies(evaluatedEvents);
        List<Incident> incidents = incidentService.generateIncidents(evaluatedEvents);
        List<TimelineEvent> timeline = timelineService.buildTimeline(evaluatedEvents);
        Evidence evidence = evidenceService.buildEvidence(evaluatedEvents);

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEvents", evaluatedEvents.size());
        stats.put("suspiciousEvents", anomalies.size());
        
        long criticalCount = evaluatedEvents.stream().filter(e -> "CRITICAL".equalsIgnoreCase(e.getSeverity())).count();
        stats.put("criticalThreats", criticalCount);
        stats.put("activeIncidents", incidents.size());

        int avgRisk = anomalies.isEmpty() ? 0 :
                (int) Math.round(anomalies.stream().mapToInt(Anomaly::getRiskScore).average().orElse(0));
        stats.put("overallRisk", avgRisk);

        AnalysisResult result = new AnalysisResult();
        result.setSuccess(true);
        result.setMessage("Processed " + evaluatedEvents.size() + " events.");
        result.setEvents(evaluatedEvents);
        result.setAnomalies(anomalies);
        result.setIncidents(incidents);
        result.setTimeline(timeline);
        result.setEvidence(evidence);
        result.setStats(stats);

        return ResponseEntity.ok(result);
    }
}
