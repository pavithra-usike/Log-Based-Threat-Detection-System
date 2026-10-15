from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
def generate_pdf_report(path,log_path,rows,alerts):
    doc=SimpleDocTemplate(path,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
    styles=getSampleStyleSheet(); story=[Paragraph("LOG-BASED THREAT DETECTION SYSTEM",styles["Title"]),Spacer(1,8),
    Paragraph("Security Analysis Report",styles["Heading2"]),
    Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",styles["BodyText"]),
    Paragraph(f"Log source: {log_path}",styles["BodyText"]),Spacer(1,12)]
    high=sum(a["severity"] in ("HIGH","CRITICAL") for a in alerts)
    summary=[["Metric","Value"],["Total log entries",str(len(rows))],["Total alerts",str(len(alerts))],["High/Critical alerts",str(high)],["Unique source IPs",str(len({r["ip"] for r in rows}))]]
    t=Table(summary,colWidths=[260,180]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#2f5597")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.5,colors.grey),("PADDING",(0,0),(-1,-1),7)]))
    story += [Paragraph("Executive Summary",styles["Heading2"]),t,Spacer(1,14),Paragraph("Identified Attacks",styles["Heading2"])]
    data=[["Rule","Time","IP","Severity","Evidence"]]+[[a["rule"][:35],a["time"][:22],a["ip"],a["severity"],a["snippet"][:90]] for a in alerts[:250]]
    if len(data)==1: data.append(["No threats detected","-","-","-","-"])
    q=Table(data,repeatRows=1,colWidths=[105,75,75,55,190]); q.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#c00000")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.35,colors.grey),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [q,PageBreak(),Paragraph("Recommended Actions",styles["Heading2"])]
    for a in ["Review HIGH and CRITICAL alerts first.","Investigate repeated source IPs.","Check threat-intelligence results.","Review the generated block list before firewall deployment.","Retain original logs for investigation."]:
        story += [Paragraph("• "+a,styles["BodyText"]),Spacer(1,4)]
    doc.build(story)
