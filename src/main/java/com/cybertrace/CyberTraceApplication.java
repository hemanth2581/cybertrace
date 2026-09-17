package com.cybertrace;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * CyberTrace - AI Digital Forensics and Incident Response Platform
 * Pure Spring Boot Application (No database, browser localStorage storage)
 */
@SpringBootApplication
public class CyberTraceApplication {

    public static void main(String[] args) {
        SpringApplication.run(CyberTraceApplication.class, args);
    }
}
