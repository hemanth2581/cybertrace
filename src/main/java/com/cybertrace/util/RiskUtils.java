package com.cybertrace.util;

import java.util.Set;

/**
 * Utility containing risk scoring thresholds, file sensitivity checks, and severity tiers.
 */
public class RiskUtils {

    private static final Set<String> SENSITIVE_FILES = Set.of(
        "passwords.txt",
        "credentials.txt",
        "secrets.txt",
        "database.sql",
        "users.csv",
        "private_keys.txt",
        "id_rsa",
        "shadow",
        ".env",
        "master.key",
        "backup.sql",
        "customer_data.csv"
    );

    /**
     * Checks if a filename or path matches known high-risk sensitive assets.
     */
    public static boolean isSensitiveFile(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            return false;
        }
        String clean = filename.trim().toLowerCase();
        
        // Direct match
        if (SENSITIVE_FILES.contains(clean)) return true;

        // Substring / extension checks
        for (String sens : SENSITIVE_FILES) {
            if (clean.endsWith(sens) || clean.contains(sens)) {
                return true;
            }
        }

        return clean.endsWith(".key") || clean.endsWith(".pem") || clean.endsWith(".kdbx");
    }

    /**
     * Maps numerical risk score (0-100) to standard SOC severity tier.
     */
    public static String getSeverityLevel(int score) {
        if (score <= 20) return "NORMAL";
        if (score <= 40) return "LOW";
        if (score <= 60) return "MEDIUM";
        if (score <= 80) return "HIGH";
        return "CRITICAL";
    }
}
