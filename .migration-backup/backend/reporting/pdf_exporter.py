import io
from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

def generate_incident_pdf(
    events: List[Dict[str, Any]],
    case_info: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    report_title: str = "Cyber Incident Investigation Report",
    filter_summary: str = "Full Dataset"
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )

    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        fontName='Helvetica-Bold',
        spaceBefore=12,
        spaceAfter=6
    )

    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )

    cell_bold_style = ParagraphStyle(
        'TableCellBold',
        parent=cell_style,
        fontName='Helvetica-Bold'
    )

    story = []

    # Title & Metadata
    story.append(Paragraph(report_title, title_style))
    meta_text = (
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"Scope: {filter_summary} | Classification: STRICTLY CONFIDENTIAL"
    )
    story.append(Paragraph(meta_text, subtitle_style))
    story.append(Spacer(1, 14))

    # Executive / Case Summary Table
    story.append(Paragraph("1. Incident Overview & Case Details", h2_style))
    
    total_events = len(events)
    crit_count = sum(1 for e in events if e.get("severity") == "Critical")
    high_count = sum(1 for e in events if e.get("severity") == "High")
    med_count = sum(1 for e in events if e.get("severity") == "Medium")
    low_count = sum(1 for e in events if e.get("severity") in ["Low", "Informational"])
    
    start_ts = events[0].get("timestamp") if events else "N/A"
    end_ts = events[-1].get("timestamp") if events else "N/A"

    summary_data = [
        [
            Paragraph("Case ID", cell_bold_style),
            Paragraph(case_info.get("case_id", "CASE-001"), cell_style),
            Paragraph("Case Status", cell_bold_style),
            Paragraph(case_info.get("status", "In Progress"), cell_style)
        ],
        [
            Paragraph("Lead Analyst", cell_bold_style),
            Paragraph(case_info.get("assigned_analyst", "SOC Analyst"), cell_style),
            Paragraph("Date Range", cell_bold_style),
            Paragraph(f"{start_ts} to {end_ts}", cell_style)
        ],
        [
            Paragraph("Total Events", cell_bold_style),
            Paragraph(str(total_events), cell_style),
            Paragraph("Severity Breakdown", cell_bold_style),
            Paragraph(f"Critical: {crit_count} | High: {high_count} | Medium: {med_count} | Low: {low_count}", cell_style)
        ]
    ]

    t_summary = Table(summary_data, colWidths=[1.3*inch, 2.2*inch, 1.4*inch, 2.3*inch])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # Analyst Notes
    if case_info.get("notes"):
        story.append(Paragraph("Analyst Investigation Notes:", cell_bold_style))
        story.append(Paragraph(case_info.get("notes"), cell_style))
        story.append(Spacer(1, 10))

    # IOCs Section
    if iocs:
        story.append(Paragraph("2. Indicators of Compromise (IOCs)", h2_style))
        ioc_table_data = [
            [
                Paragraph("Indicator", cell_bold_style),
                Paragraph("Type", cell_bold_style),
                Paragraph("Detection Rule / Context", cell_bold_style),
                Paragraph("Occurrences", cell_bold_style),
                Paragraph("Status", cell_bold_style)
            ]
        ]
        
        # Take up to 25 IOCs in summary
        for ioc in iocs[:25]:
            stat = ioc.get("analyst_status", "Observed")
            stat_color = colors.HexColor('#b91c1c') if stat == "Confirmed Threat" else (colors.HexColor('#047857') if stat == "False Positive" else colors.HexColor('#d97706'))
            stat_p = Paragraph(f"<font color='{stat_color.hexval()}'>{stat}</font>", cell_bold_style)

            ioc_table_data.append([
                Paragraph(str(ioc.get("indicator_value") or "-"), cell_style),
                Paragraph(str(ioc.get("indicator_type") or "-"), cell_style),
                Paragraph(str(ioc.get("detection_rule") or "-"), cell_style),
                Paragraph(str(ioc.get("occurrence_count") or 1), cell_style),
                stat_p
            ])

        t_ioc = Table(ioc_table_data, colWidths=[1.8*inch, 1.1*inch, 2.4*inch, 0.8*inch, 1.1*inch])
        t_ioc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_ioc)
        story.append(Spacer(1, 12))

    # Chronological Incident Events Table
    story.append(Paragraph(f"3. Chronological Incident Event Timeline ({min(len(events), 150)} displayed)", h2_style))

    events_table_data = [
        [
            Paragraph("Timestamp (UTC)", cell_bold_style),
            Paragraph("Source", cell_bold_style),
            Paragraph("Severity", cell_bold_style),
            Paragraph("Event Type / Action", cell_bold_style),
            Paragraph("Source IP -> Dest IP", cell_bold_style),
            Paragraph("User / Process", cell_bold_style),
            Paragraph("Description", cell_bold_style)
        ]
    ]

    for evt in events[:150]:
        sev = evt.get("severity") or "Low"
        sev_color = colors.HexColor('#dc2626') if sev == "Critical" else (colors.HexColor('#ea580c') if sev == "High" else (colors.HexColor('#d97706') if sev == "Medium" else colors.HexColor('#16a34a')))
        sev_p = Paragraph(f"<font color='{sev_color.hexval()}'>{sev}</font>", cell_bold_style)

        flow = f"{evt.get('source_ip') or '-'}"
        if evt.get('destination_ip'):
            flow += f" -> {evt.get('destination_ip')}"

        entity = f"{evt.get('username') or '-'}"
        if evt.get('process_name'):
            entity += f" ({evt.get('process_name')})"

        events_table_data.append([
            Paragraph(str(evt.get("timestamp") or "-"), cell_style),
            Paragraph(str(evt.get("log_source") or "-"), cell_style),
            sev_p,
            Paragraph(f"{evt.get('event_type') or '-'}<br/>{evt.get('action') or ''}", cell_style),
            Paragraph(flow, cell_style),
            Paragraph(entity, cell_style),
            Paragraph(str(evt.get("description") or "-")[:120], cell_style)
        ])

    t_events = Table(events_table_data, colWidths=[1.1*inch, 0.65*inch, 0.65*inch, 1.2*inch, 1.2*inch, 0.9*inch, 1.5*inch])
    t_events.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_events)

    doc.build(story)
    return buffer.getvalue()
