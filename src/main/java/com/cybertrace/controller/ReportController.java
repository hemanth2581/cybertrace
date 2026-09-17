package com.cybertrace.controller;

import com.cybertrace.dto.AnalysisResult;
import com.cybertrace.model.Evidence;
import com.cybertrace.model.Incident;
import com.cybertrace.model.SecurityEvent;
import com.cybertrace.model.TimelineEvent;
import com.cybertrace.service.PdfReportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/report")
@CrossOrigin(origins = "*")
public class ReportController {

    private final PdfReportService pdfService;

    public ReportController(PdfReportService pdfService) {
        this.pdfService = pdfService;
    }

    @PostMapping("/pdf")
    public ResponseEntity<byte[]> generatePdfReport(@RequestBody AnalysisResult data) {
        Incident incident = (data.getIncidents() != null && !data.getIncidents().isEmpty()) 
                ? data.getIncidents().get(0) : new Incident();
        List<SecurityEvent> events = (data.getEvents() != null) ? data.getEvents() : List.of();
        List<TimelineEvent> timeline = (data.getTimeline() != null) ? data.getTimeline() : List.of();
        Evidence evidence = (data.getEvidence() != null) ? data.getEvidence() : new Evidence();

        byte[] pdfBytes = pdfService.generateIncidentReportPdf(incident, events, timeline, evidence);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        String filename = "CyberTrace_Report_" + (incident.getIncidentId() != null ? incident.getIncidentId() : "INC-001") + ".pdf";
        headers.setContentDispositionFormData("attachment", filename);

        return ResponseEntity.ok()
                .headers(headers)
                .body(pdfBytes);
    }
}
