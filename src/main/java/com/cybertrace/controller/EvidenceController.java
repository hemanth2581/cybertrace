package com.cybertrace.controller;

import com.cybertrace.model.Evidence;
import com.cybertrace.model.SecurityEvent;
import com.cybertrace.service.EvidenceService;
import com.cybertrace.service.RiskAnalysisService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/evidence")
@CrossOrigin(origins = "*")
public class EvidenceController {

    private final EvidenceService evidenceService;
    private final RiskAnalysisService riskService;

    public EvidenceController(EvidenceService evidenceService, RiskAnalysisService riskService) {
        this.evidenceService = evidenceService;
        this.riskService = riskService;
    }

    @PostMapping("/generate")
    public ResponseEntity<Evidence> generateEvidence(@RequestBody List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return ResponseEntity.ok(new Evidence());
        }
        List<SecurityEvent> evaluated = riskService.analyzeEvents(events);
        Evidence evidence = evidenceService.buildEvidence(evaluated);
        return ResponseEntity.ok(evidence);
    }
}
