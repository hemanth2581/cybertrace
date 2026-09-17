package com.cybertrace.util;

import java.util.regex.Pattern;

/**
 * Utility for evaluating IPv4 addresses against private RFC 1918 ranges.
 */
public class IpUtils {

    private static final Pattern IPV4_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    /**
     * Checks if the given IP address is private/internal (RFC 1918 / loopback).
     */
    public static boolean isInternalIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return true;
        }

        String trimmed = ip.trim();

        if ("localhost".equalsIgnoreCase(trimmed) || "127.0.0.1".equals(trimmed) || "::1".equals(trimmed)) {
            return true;
        }

        if (!IPV4_PATTERN.matcher(trimmed).matches()) {
            return false;
        }

        String[] parts = trimmed.split("\\.");
        if (parts.length != 4) return false;

        try {
            int p0 = Integer.parseInt(parts[0]);
            int p1 = Integer.parseInt(parts[1]);

            // 10.0.0.0 - 10.255.255.255 (10/8)
            if (p0 == 10) return true;

            // 192.168.0.0 - 192.168.255.255 (192.168/16)
            if (p0 == 192 && p1 == 168) return true;

            // 172.16.0.0 - 172.31.255.255 (172.16/12)
            if (p0 == 172 && (p1 >= 16 && p1 <= 31)) return true;

            // 127.0.0.0/8 loopback
            if (p0 == 127) return true;

        } catch (NumberFormatException e) {
            return false;
        }

        return false;
    }

    /**
     * Checks if the given IP address is external (non-private).
     */
    public static boolean isExternalIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) return false;
        return !isInternalIp(ip);
    }
}
