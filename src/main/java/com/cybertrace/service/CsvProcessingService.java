package com.cybertrace.service;

import com.cybertrace.model.SecurityEvent;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Service responsible for validating and parsing RFC-compliant CSV security audit logs.
 */
@Service
public class CsvProcessingService {

    private static final List<String> REQUIRED_COLUMNS = List.of(
        "timestamp", "user", "device", "ip", "action"
    );

    /**
     * Parses CSV text content into normalized SecurityEvent objects.
     */
    public List<SecurityEvent> parseCsv(String csvContent) {
        if (csvContent == null || csvContent.trim().isEmpty()) {
            throw new IllegalArgumentException("No security events were found.");
        }

        try (StringReader reader = new StringReader(csvContent);
             CSVParser parser = CSVFormat.DEFAULT.builder()
                     .setHeader()
                     .setSkipHeaderRecord(true)
                     .setIgnoreHeaderCase(true)
                     .setTrim(true)
                     .build()
                     .parse(reader)) {

            return processRecords(parser);

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to process this CSV file. Please check the file format.");
        }
    }

    /**
     * Parses CSV input stream into normalized SecurityEvent objects.
     */
    public List<SecurityEvent> parseCsv(InputStream inputStream) {
        if (inputStream == null) {
            throw new IllegalArgumentException("No security events were found.");
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
             CSVParser parser = CSVFormat.DEFAULT.builder()
                     .setHeader()
                     .setSkipHeaderRecord(true)
                     .setIgnoreHeaderCase(true)
                     .setTrim(true)
                     .build()
                     .parse(reader)) {

            return processRecords(parser);

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to process this CSV file. Please check the file format.");
        }
    }

    private List<SecurityEvent> processRecords(CSVParser parser) {
        Map<String, Integer> headerMap = parser.getHeaderMap();
        if (headerMap == null || headerMap.isEmpty()) {
            throw new IllegalArgumentException("Invalid CSV format. Required columns are missing.");
        }

        // Validate required headers (case-insensitive)
        Set<String> normalizedHeaders = new HashSet<>();
        for (String h : headerMap.keySet()) {
            normalizedHeaders.add(h.toLowerCase().trim());
        }

        for (String req : REQUIRED_COLUMNS) {
            if (!normalizedHeaders.contains(req)) {
                throw new IllegalArgumentException("Invalid CSV format. Required columns are missing: " + req);
            }
        }

        List<SecurityEvent> events = new ArrayList<>();
        int index = 1;

        for (CSVRecord record : parser) {
            String timestamp = getRecordValue(record, "timestamp", "");
            String user = getRecordValue(record, "user", "UNKNOWN");
            String device = getRecordValue(record, "device", "UNKNOWN");
            String ip = getRecordValue(record, "ip", "0.0.0.0");
            String action = getRecordValue(record, "action", "UNKNOWN");
            String file = getRecordValue(record, "file", "");
            
            int dataSize = 0;
            String dataSizeStr = getRecordValue(record, "data_size", "");
            if (dataSizeStr.isEmpty()) {
                dataSizeStr = getRecordValue(record, "datasize", "");
            }
            if (!dataSizeStr.isEmpty()) {
                try {
                    // Strip 'MB' or non-digit chars if present
                    String cleanDigits = dataSizeStr.replaceAll("[^0-9]", "");
                    if (!cleanDigits.isEmpty()) {
                        dataSize = Integer.parseInt(cleanDigits);
                    }
                } catch (NumberFormatException ignored) {}
            }

            if (!timestamp.isEmpty() || !user.isEmpty() || !action.isEmpty()) {
                String eventId = String.format("EVT-%03d", index++);
                SecurityEvent event = new SecurityEvent(eventId, timestamp, user, device, ip, action, file, dataSize);
                events.add(event);
            }
        }

        if (events.isEmpty()) {
            throw new IllegalArgumentException("No security events were found.");
        }

        return events;
    }

    private String getRecordValue(CSVRecord record, String column, String defaultValue) {
        for (String name : record.getParser().getHeaderNames()) {
            if (name.equalsIgnoreCase(column)) {
                try {
                    String val = record.get(name);
                    return (val != null) ? val.trim() : defaultValue;
                } catch (IllegalArgumentException e) {
                    return defaultValue;
                }
            }
        }
        return defaultValue;
    }
}
