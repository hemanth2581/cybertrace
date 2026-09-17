package com.cybertrace.controller;

import com.cybertrace.dto.AnalysisResult;
import com.cybertrace.model.*;
import com.cybertrace.service.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST Controller for CSV log ingestion and forensic telemetry analysis.
 */
@RestController
@RequestMapping("/api/events")
@CrossOrigin(origins = "*")
public class SecurityEventController {

    private final CsvProcessingService csvService;
    private final RiskAnalysisService riskService;
    private final AnomalyDetectionService anomalyService;
    private final IncidentService incidentService;
    private final TimelineService timelineService;
    private final EvidenceService evidenceService;

    public SecurityEventController(CsvProcessingService csvService,
                                   RiskAnalysisService riskService,
                                   AnomalyDetectionService anomalyService,
                                   IncidentService incidentService,
                                   TimelineService timelineService,
                                   EvidenceService evidenceService) {
        this.csvService = csvService;
        this.riskService = riskService;
        this.anomalyService = anomalyService;
        this.incidentService = incidentService;
        this.timelineService = timelineService;
        this.evidenceService = evidenceService;
    }

    /**
     * Upload and analyze multipart CSV security audit log.
     */
    @PostMapping("/analyze")
    public ResponseEntity<AnalysisResult> uploadAndAnalyze(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(AnalysisResult.error("Uploaded file is empty. Please select a valid CSV file."));
        }

        try (InputStream inputStream = file.getInputStream()) {
            List<SecurityEvent> rawEvents = csvService.parseCsv(inputStream);
            return processAndBuildResult(rawEvents);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AnalysisResult.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(AnalysisResult.error("Failed to process CSV file: " + e.getMessage()));
        }
    }

    /**
     * Analyze raw CSV string text.
     */
    @PostMapping("/analyze-text")
    public ResponseEntity<AnalysisResult> analyzeCsvText(@RequestBody String csvText) {
        try {
            List<SecurityEvent> rawEvents = csvService.parseCsv(csvText);
            return processAndBuildResult(rawEvents);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AnalysisResult.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(AnalysisResult.error("Failed to process CSV: " + e.getMessage()));
        }
    }

    private ResponseEntity<AnalysisResult> processAndBuildResult(List<SecurityEvent> rawEvents) {
        // 1. Calculate risk scores and reason
        List<SecurityEvent> evaluatedEvents = riskService.analyzeEvents(rawEvents);

        // 2. Filter anomalous events
        List<Anomaly> anomalies = anomalyService.detectAnomalies(evaluatedEvents);

        // 3. Correlate incidents
        List<Incident> incidents = incidentService.generateIncidents(evaluatedEvents);

        // 4. Build chronological attack timeline
        List<TimelineEvent> timeline = timelineService.buildTimeline(evaluatedEvents);

        // 5. Generate entity relationship evidence graph
        Evidence evidence = evidenceService.buildEvidence(evaluatedEvents);

        // 6. Aggregate stats
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
        result.setMessage("Log analyzed successfully. " + evaluatedEvents.size() + " events evaluated.");
        result.setEvents(evaluatedEvents);
        result.setAnomalies(anomalies);
        result.setIncidents(incidents);
        result.setTimeline(timeline);
        result.setEvidence(evidence);
        result.setStats(stats);

        return ResponseEntity.ok(result);
    }
}
