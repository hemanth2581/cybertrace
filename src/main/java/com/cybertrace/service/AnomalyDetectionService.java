package com.cybertrace.service;

import com.cybertrace.model.Anomaly;
import com.cybertrace.model.SecurityEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Service that isolates suspicious activities and anomalous security events.
 */
@Service
public class AnomalyDetectionService {

    /**
     * Extracts anomalies from analyzed security events.
     */
    public List<Anomaly> detectAnomalies(List<SecurityEvent> events) {
        List<Anomaly> anomalies = new ArrayList<>();
        if (events == null) return anomalies;

        int count = 1;
        for (SecurityEvent event : events) {
            // An event is anomalous if riskScore > 20 or severity != NORMAL
            if (event.getRiskScore() > 20 || !"NORMAL".equalsIgnoreCase(event.getSeverity())) {
                String anomId = String.format("ANOM-%03d", count++);
                anomalies.add(Anomaly.fromSecurityEvent(event, anomId));
            }
        }

        return anomalies;
    }
}
