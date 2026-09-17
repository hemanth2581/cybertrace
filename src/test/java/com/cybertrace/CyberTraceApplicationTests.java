package com.cybertrace;

import com.cybertrace.dto.AnalysisResult;
import com.cybertrace.dto.InvestigatorRequest;
import com.cybertrace.dto.InvestigatorResponse;
import com.cybertrace.model.*;
import com.cybertrace.service.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class CyberTraceApplicationTests {

    @Autowired
    private CsvProcessingService csvService;

    @Autowired
    private RiskAnalysisService riskService;

    @Autowired
    private AnomalyDetectionService anomalyService;

    @Autowired
    private IncidentService incidentService;

    @Autowired
    private TimelineService timelineService;

    @Autowired
    private EvidenceService evidenceService;

    @Autowired
    private InvestigatorService investigatorService;

    @Test
    void contextLoads() {
        assertNotNull(csvService);
        assertNotNull(riskService);
    }

    @Test
    void testAccountCompromiseFlow() {
        String csv = "timestamp,user,device,ip,action,file,data_size\n" +
                "2026-09-17 10:01:00,Shiva,DEV01,192.168.1.10,LOGIN,,0\n" +
                "2026-09-17 10:03:00,Shiva,DEV01,185.23.45.10,FAILED_LOGIN,,0\n" +
                "2026-09-17 10:08:00,Shiva,DEV01,185.23.45.10,FILE_ACCESS,passwords.txt,0\n" +
                "2026-09-17 10:12:00,Shiva,DEV01,185.23.45.10,DATA_TRANSFER,,850\n" +
                "2026-09-17 10:15:00,Shiva,DEV01,185.23.45.10,PRIVILEGE_ESCALATION,,0";

        List<SecurityEvent> events = csvService.parseCsv(csv);
        assertEquals(5, events.size());

        List<SecurityEvent> analyzed = riskService.analyzeEvents(events);
        List<Anomaly> anomalies = anomalyService.detectAnomalies(analyzed);
        assertTrue(anomalies.size() >= 4);

        List<Incident> incidents = incidentService.generateIncidents(analyzed);
        assertEquals(1, incidents.size());
        assertEquals("Account Compromise Detected", incidents.get(0).getTitle());
        assertEquals("Shiva", incidents.get(0).getAffectedUser());
        assertEquals("185.23.45.10", incidents.get(0).getSourceIP());

        List<TimelineEvent> timeline = timelineService.buildTimeline(analyzed);
        assertEquals(5, timeline.size());
        assertTrue(timeline.get(1).isFirstSuspicious());

        Evidence evidence = evidenceService.buildEvidence(analyzed);
        assertEquals("Shiva", evidence.getUser());
        assertEquals("DEV01", evidence.getDevice());
        assertEquals("185.23.45.10", evidence.getIp());
        assertEquals("passwords.txt", evidence.getFile());

        // Test Investigator Questions
        InvestigatorRequest req1 = new InvestigatorRequest();
        req1.setQuestion("What happened?");
        req1.setEvents(analyzed);
        req1.setEvidence(evidence);
        req1.setIncidents(incidents);
        InvestigatorResponse res1 = investigatorService.answerQuestion(req1);
        assertTrue(res1.getAnswer().contains("Shiva"));

        InvestigatorRequest req2 = new InvestigatorRequest();
        req2.setQuestion("Who was involved?");
        req2.setEvents(analyzed);
        req2.setEvidence(evidence);
        InvestigatorResponse res2 = investigatorService.answerQuestion(req2);
        assertTrue(res2.getAnswer().contains("Shiva"));
    }
}
