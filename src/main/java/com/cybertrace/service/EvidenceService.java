package com.cybertrace.service;

import com.cybertrace.model.Evidence;
import com.cybertrace.model.SecurityEvent;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Service that builds the entity relationship chain:
 * USER -> DEVICE -> IP -> FILE -> DATA TRANSFER
 */
@Service
public class EvidenceService {

    /**
     * Extracts correlated evidence chain from evaluated events.
     */
    public Evidence buildEvidence(List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return new Evidence();
        }

        // Prioritize suspicious events first to capture attack chain
        List<SecurityEvent> suspicious = events.stream()
                .filter(e -> e.getRiskScore() > 20 || !"NORMAL".equalsIgnoreCase(e.getSeverity()))
                .toList();

        List<SecurityEvent> sourceEvents = !suspicious.isEmpty() ? suspicious : events;

        String primaryUser = sourceEvents.get(0).getUser();
        String primaryDevice = sourceEvents.get(0).getDevice();
        String primaryIp = "0.0.0.0";
        String accessedFile = "None";
        int totalTransferMb = 0;
        List<String> suspiciousNodes = new ArrayList<>();

        for (SecurityEvent ev : sourceEvents) {
            if (!"0.0.0.0".equals(ev.getIp()) && !"127.0.0.1".equals(ev.getIp())) {
                primaryIp = ev.getIp();
            }
            if (ev.getFile() != null && !ev.getFile().isEmpty() && "None".equals(accessedFile)) {
                accessedFile = ev.getFile();
            }
            totalTransferMb += ev.getDataSize();
        }

        // Tag suspicious nodes
        if (!suspicious.isEmpty()) {
            suspiciousNodes.add("USER:" + primaryUser);
            suspiciousNodes.add("DEVICE:" + primaryDevice);
            suspiciousNodes.add("IP:" + primaryIp);
            if (!"None".equals(accessedFile)) {
                suspiciousNodes.add("FILE:" + accessedFile);
            }
            if (totalTransferMb >= 500) {
                suspiciousNodes.add("TRANSFER:" + totalTransferMb + " MB");
            }
        }

        String transferStr = (totalTransferMb > 0) ? (totalTransferMb + " MB") : "0 MB";

        return new Evidence(
                primaryUser,
                primaryDevice,
                primaryIp,
                accessedFile,
                transferStr,
                suspiciousNodes
        );
    }
}
