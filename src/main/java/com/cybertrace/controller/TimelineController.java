package com.cybertrace.controller;

import com.cybertrace.model.SecurityEvent;
import com.cybertrace.model.TimelineEvent;
import com.cybertrace.service.RiskAnalysisService;
import com.cybertrace.service.TimelineService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/timeline")
@CrossOrigin(origins = "*")
public class TimelineController {

    private final TimelineService timelineService;
    private final RiskAnalysisService riskService;

    public TimelineController(TimelineService timelineService, RiskAnalysisService riskService) {
        this.timelineService = timelineService;
        this.riskService = riskService;
    }

    @PostMapping("/generate")
    public ResponseEntity<List<TimelineEvent>> generateTimeline(@RequestBody List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return ResponseEntity.ok(List.of());
        }
        List<SecurityEvent> evaluated = riskService.analyzeEvents(events);
        List<TimelineEvent> timeline = timelineService.buildTimeline(evaluated);
        return ResponseEntity.ok(timeline);
    }
}
