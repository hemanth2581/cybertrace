package com.cybertrace.controller;

import com.cybertrace.dto.InvestigatorRequest;
import com.cybertrace.dto.InvestigatorResponse;
import com.cybertrace.service.InvestigatorService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/investigator")
@CrossOrigin(origins = "*")
public class InvestigatorController {

    private final InvestigatorService investigatorService;

    public InvestigatorController(InvestigatorService investigatorService) {
        this.investigatorService = investigatorService;
    }

    @PostMapping("/query")
    public ResponseEntity<InvestigatorResponse> queryInvestigator(@RequestBody InvestigatorRequest request) {
        InvestigatorResponse response = investigatorService.answerQuestion(request);
        return ResponseEntity.ok(response);
    }
}
