package com.cybertrace.controller;

import com.cybertrace.model.Incident;
import com.cybertrace.model.SecurityEvent;
import com.cybertrace.service.IncidentService;
import com.cybertrace.service.RiskAnalysisService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/incidents")
@CrossOrigin(origins = "*")
public class IncidentController {

    private final IncidentService incidentService;
    private final RiskAnalysisService riskService;

    public IncidentController(IncidentService incidentService, RiskAnalysisService riskService) {
        this.incidentService = incidentService;
        this.riskService = riskService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<List<Incident>> analyzeIncidents(@RequestBody List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return ResponseEntity.ok(List.of());
        }
        List<SecurityEvent> evaluated = riskService.analyzeEvents(events);
        List<Incident> incidents = incidentService.generateIncidents(evaluated);
        return ResponseEntity.ok(incidents);
    }
}
