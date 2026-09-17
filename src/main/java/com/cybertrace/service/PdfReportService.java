package com.cybertrace.service;

import com.cybertrace.model.Evidence;
import com.cybertrace.model.Incident;
import com.cybertrace.model.SecurityEvent;
import com.cybertrace.model.TimelineEvent;
import com.lowagie.text.*;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.util.List;

/**
 * Service that compiles professional Digital Forensics Incident Report PDFs.
 */
@Service
public class PdfReportService {

    public byte[] generateIncidentReportPdf(Incident incident, 
                                            List<SecurityEvent> events, 
                                            List<TimelineEvent> timeline, 
                                            Evidence evidence) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Document document = new Document(PageSize.A4, 36, 36, 36, 36);
            PdfWriter.getInstance(document, out);
            document.open();

            // Fonts & Colors
            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, new Color(2, 132, 199)); // #0284c7
            Font subTitleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, new Color(15, 23, 42));
            Font sectionFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, new Color(2, 132, 199));
            Font bodyFont = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(51, 65, 85));
            Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, new Color(15, 23, 42));
            Font tableHeaderFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.WHITE);
            Font tableBodyFont = FontFactory.getFont(FontFactory.HELVETICA, 8, new Color(30, 41, 59));

            // Header Banner Table
            PdfPTable headerTable = new PdfPTable(2);
            headerTable.setWidthPercentage(100);
            headerTable.setWidths(new float[]{60, 40});

            PdfPCell leftHeader = new PdfPCell();
            leftHeader.setBorder(Rectangle.NO_BORDER);
            leftHeader.addElement(new Paragraph("CYBERTRACE", titleFont));
            leftHeader.addElement(new Paragraph("Digital Forensics Incident Report", subTitleFont));
            headerTable.addCell(leftHeader);

            PdfPCell rightHeader = new PdfPCell();
            rightHeader.setBorder(Rectangle.NO_BORDER);
            rightHeader.setHorizontalAlignment(Element.ALIGN_RIGHT);
            rightHeader.addElement(new Paragraph("Case ID: " + (incident != null ? incident.getIncidentId() : "INC-001"), boldFont));
            rightHeader.addElement(new Paragraph("Generated: " + java.time.LocalDate.now(), bodyFont));
            rightHeader.addElement(new Paragraph("Status: " + (incident != null ? incident.getStatus() : "CLOSED"), bodyFont));
            headerTable.addCell(rightHeader);

            document.add(headerTable);
            document.add(new Paragraph(" "));

            // Incident Executive Summary Table
            PdfPTable summaryTable = new PdfPTable(4);
            summaryTable.setWidthPercentage(100);
            summaryTable.setWidths(new float[]{25, 25, 25, 25});

            addCellToTable(summaryTable, "Incident ID", tableHeaderFont, new Color(15, 23, 42));
            addCellToTable(summaryTable, "Threat Level", tableHeaderFont, new Color(15, 23, 42));
            addCellToTable(summaryTable, "Affected User", tableHeaderFont, new Color(15, 23, 42));
            addCellToTable(summaryTable, "Source IP", tableHeaderFont, new Color(15, 23, 42));

            String sev = (incident != null) ? incident.getSeverity() : "NORMAL";
            Color sevColor = "CRITICAL".equalsIgnoreCase(sev) ? new Color(220, 38, 38) :
                             "HIGH".equalsIgnoreCase(sev) ? new Color(234, 88, 12) :
                             "MEDIUM".equalsIgnoreCase(sev) ? new Color(217, 119, 6) : new Color(22, 163, 74);

            addCellToTable(summaryTable, incident != null ? incident.getIncidentId() : "INC-001", boldFont, Color.WHITE);
            
            PdfPCell sevCell = new PdfPCell(new Phrase(sev, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, sevColor)));
            sevCell.setPadding(6);
            summaryTable.addCell(sevCell);

            addCellToTable(summaryTable, incident != null ? incident.getAffectedUser() : (evidence != null ? evidence.getUser() : "N/A"), bodyFont, Color.WHITE);
            addCellToTable(summaryTable, incident != null ? incident.getSourceIP() : (evidence != null ? evidence.getIp() : "N/A"), bodyFont, Color.WHITE);

            document.add(summaryTable);
            document.add(new Paragraph(" "));

            // Section: Incident Overview & Scope
            document.add(new Paragraph("1. Incident Summary & Scope", sectionFont));
            String title = (incident != null) ? incident.getTitle() : "Forensic Audit Assessment";
            String firstEvent = (incident != null) ? incident.getFirstSuspiciousEvent() : "None";
            int suspCount = (incident != null) ? incident.getSuspiciousEventCount() : 0;

            Paragraph summaryPara = new Paragraph(
                    "CyberTrace digital forensics engine detected a " + sev + " severity incident (" + title + "). " +
                    "A total of " + suspCount + " suspicious events were flagged. " +
                    "Initial infiltration signature: " + firstEvent + ".",
                    bodyFont
            );
            document.add(summaryPara);
            document.add(new Paragraph(" "));

            // Section: Evidence Correlation Chain
            document.add(new Paragraph("2. Forensic Evidence Correlation Chain", sectionFont));
            if (evidence != null) {
                PdfPTable evTable = new PdfPTable(5);
                evTable.setWidthPercentage(100);
                evTable.setWidths(new float[]{20, 20, 20, 20, 20});

                addCellToTable(evTable, "User Principal", tableHeaderFont, new Color(2, 132, 199));
                addCellToTable(evTable, "Target Device", tableHeaderFont, new Color(2, 132, 199));
                addCellToTable(evTable, "Source IP", tableHeaderFont, new Color(2, 132, 199));
                addCellToTable(evTable, "Accessed File", tableHeaderFont, new Color(2, 132, 199));
                addCellToTable(evTable, "Data Transfer", tableHeaderFont, new Color(2, 132, 199));

                addCellToTable(evTable, evidence.getUser(), bodyFont, Color.WHITE);
                addCellToTable(evTable, evidence.getDevice(), bodyFont, Color.WHITE);
                addCellToTable(evTable, evidence.getIp(), bodyFont, Color.WHITE);
                addCellToTable(evTable, evidence.getFile(), bodyFont, Color.WHITE);
                addCellToTable(evTable, evidence.getDataTransfer(), bodyFont, Color.WHITE);

                document.add(evTable);
            }
            document.add(new Paragraph(" "));

            // Section: Attack Timeline Reconstruction
            document.add(new Paragraph("3. Chronological Attack Timeline", sectionFont));
            if (timeline != null && !timeline.isEmpty()) {
                PdfPTable tlTable = new PdfPTable(5);
                tlTable.setWidthPercentage(100);
                tlTable.setWidths(new float[]{20, 22, 18, 15, 25});

                addCellToTable(tlTable, "Timestamp", tableHeaderFont, new Color(15, 23, 42));
                addCellToTable(tlTable, "Event Action", tableHeaderFont, new Color(15, 23, 42));
                addCellToTable(tlTable, "Device / IP", tableHeaderFont, new Color(15, 23, 42));
                addCellToTable(tlTable, "Risk Score", tableHeaderFont, new Color(15, 23, 42));
                addCellToTable(tlTable, "Forensic Note", tableHeaderFont, new Color(15, 23, 42));

                for (TimelineEvent t : timeline) {
                    addCellToTable(tlTable, t.getTimestamp(), tableBodyFont, Color.WHITE);
                    addCellToTable(tlTable, t.getEventType(), tableBodyFont, Color.WHITE);
                    addCellToTable(tlTable, t.getDevice() + " / " + t.getIp(), tableBodyFont, Color.WHITE);
                    addCellToTable(tlTable, t.getRiskScore() + " (" + t.getSeverity() + ")", tableBodyFont, Color.WHITE);
                    addCellToTable(tlTable, t.getDescription(), tableBodyFont, Color.WHITE);
                }
                document.add(tlTable);
            }
            document.add(new Paragraph(" "));

            // Section: Recommended Actions
            document.add(new Paragraph("4. Recommended Containment & Remediation Actions", sectionFont));
            if (incident != null && incident.getRecommendations() != null && !incident.getRecommendations().isEmpty()) {
                com.lowagie.text.List list = new com.lowagie.text.List(com.lowagie.text.List.ORDERED);
                for (String rec : incident.getRecommendations()) {
                    list.add(new ListItem(rec, bodyFont));
                }
                document.add(list);
            } else {
                document.add(new Paragraph("• Maintain regular security monitoring and verify standard MFA enforcement.", bodyFont));
            }

            document.close();
            return out.toByteArray();

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate digital forensics PDF report: " + e.getMessage(), e);
        }
    }

    private void addCellToTable(PdfPTable table, String text, Font font, Color bgColor) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "", font));
        cell.setBackgroundColor(bgColor);
        cell.setPadding(5);
        table.addCell(cell);
    }
}
