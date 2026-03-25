from datetime import datetime
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.platypus import Table, TableStyle
import matplotlib.pyplot as plt
import os
import matplotlib
matplotlib.use('Agg')

def create_pie_chart(attack_stats, filename):
    labels = [k for k, v in attack_stats.items() if v > 0]
    sizes = [v for k, v in attack_stats.items() if v > 0]
    if not sizes: return False
    fig, ax = plt.subplots(figsize=(6, 5))
    colors_list = ['#ff3366', '#9333ea', '#ef4444', '#ffa500', '#00ffaa']
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors_list)
    ax.axis('equal')
    plt.title('Critical Threat Distribution', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(filename, dpi=120)
    plt.close()
    return True

def create_bar_chart(protocol_stats, filename):
    labels = [k for k, v in protocol_stats.items() if v > 0]
    values = [v for k, v in protocol_stats.items() if v > 0]
    if not values: return False
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.bar(labels, values, color='#00a2ff', alpha=0.8)
    plt.title('Attack Protocol Analysis', fontsize=14, fontweight='bold')
    plt.ylabel('Incident Count')
    plt.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tight_layout()
    plt.savefig(filename, dpi=120)
    plt.close()
    return True

def generate_merged_report(packets, attack_stats, protocol_stats):
    """Generates a professional table-based Forensic Report with dynamic severity."""
    # Limit to latest 350 packets to maintain a 10-15 page layout
    packets = packets[-350:]
    
    os.makedirs('reports', exist_ok=True)
    temp_dir = os.path.join('reports', 'temp_forensics')
    os.makedirs(temp_dir, exist_ok=True)
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = os.path.join(temp_dir, f"SUDO_HEX_Forensic_Report_{timestamp_str}.pdf")
    pie_file = os.path.join(temp_dir, f"pie_{timestamp_str}.png")
    bar_file = os.path.join(temp_dir, f"bar_{timestamp_str}.png")

    has_pie = create_pie_chart(attack_stats, pie_file)
    has_bar = create_bar_chart(protocol_stats, bar_file)

    c = canvas.Canvas(pdf_filename, pagesize=A4)
    width, height = A4

    # Header - Professional Branding
    c.setStrokeColor(colors.black)
    c.setLineWidth(2)
    c.line(40, height - 60, width - 40, height - 60)
    c.setFont("Helvetica-Bold", 24)
    c.drawString(40, height - 50, "SUDO HEX: FORENSIC IR REPORT")
    c.setFont("Helvetica", 10)
    c.drawString(40, height - 75, f"REPORT ID: SH-{timestamp_str}")
    c.drawString(40, height - 90, f"GENERATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(40, height - 105, "CLASSIFICATION: CRITICAL FORENSIC DATA")

    # Section 1: Executive Summary
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, height - 140, "1. EXECUTIVE SUMMARY")
    c.setFont("Helvetica", 11)
    summary_text = f"This forensic report provides a live audit of high-impact attacks detected. Normal traffic and reconnaissance have been omitted. Total critical records analyzed: {len(packets)}."
    
    text_obj = c.beginText(40, height - 160) # type: ignore
    text_obj.setFont("Helvetica", 11)
    text_obj.setLeading(14)
    for line in [summary_text[:95], summary_text[95:]]: text_obj.textLine(line)
    c.drawText(text_obj)

    if has_pie: c.drawImage(pie_file, 40, height - 440, width=220, height=180)
    if has_bar: c.drawImage(bar_file, 300, height - 440, width=220, height=180)
    c.showPage()

    # Section 2: Forensics Table
    data = [["Timestamp", "Attack Technical Identity", "OSI Layer Targeted", "Severity", "Source IP", "Target IP", "Conf"]]
    for p in packets:
        sev = str(p.get('severity', 'High')).upper()
        # Handle timestamp as either a datetime object or a string
        ts = p.get('timestamp', '')
        if hasattr(ts, 'strftime'):
            time_str = ts.strftime('%H:%M:%S')
        else:
            parts = str(ts).split(' ')
            time_str = parts[1] if len(parts) > 1 else str(ts)
        # Handle confidence as float or string
        conf = p.get('confidence', 99.9)
        conf_str = f"{float(conf):.1f}%" if conf != '' else '99.9%'
        data.append([
            time_str,
            p.get('attack_type', ''),
            p.get('osi_layer', 'N/A'),
            sev,
            p.get('source_ip', ''),
            p.get('destination_ip', ''),
            conf_str
        ])

    rows_per_page = 35
    for i in range(0, len(data), rows_per_page):
        chunk = data[i:i + rows_per_page]
        if i > 0: chunk.insert(0, data[0])
        table = Table(chunk, colWidths=[55, 130, 95, 55, 80, 80, 40])
        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.black),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')
        ])
        # Color code severity in the table
        for idx, row in enumerate(chunk):
            if row[3] == 'CRITICAL': style.add('TEXTCOLOR', (3, idx), (3, idx), colors.red)
            elif row[3] == 'HIGH': style.add('TEXTCOLOR', (3, idx), (3, idx), colors.orange)
        
        table.setStyle(style)
        w, h = table.wrapOn(c, 40, height - 100)
        table.drawOn(c, 40, height - 60 - h)
        c.setFont("Helvetica", 8)
        c.drawString(width - 60, 30, f"P. {c.getPageNumber()}")
        c.showPage()

    c.save()
    for f in [pie_file, bar_file]:
        if os.path.exists(f): os.remove(f)
    return os.path.abspath(pdf_filename)
