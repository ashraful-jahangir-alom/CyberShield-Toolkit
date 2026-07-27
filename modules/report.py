from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def build_report(path, target, scans, score):
    styles = getSampleStyleSheet(); story = [Spacer(1, 1.3*inch), Paragraph('CyberShield Toolkit', styles['Title']), Paragraph('Authorized Security Assessment Report', styles['Heading2']), Spacer(1, .35*inch), Paragraph(f'Target: {target}', styles['BodyText']), Paragraph(f'Overall Security Score: {score}/100', styles['BodyText']), Spacer(1, .3*inch), Paragraph('Executive Summary', styles['Heading2']), Paragraph('This report contains non-invasive observations from authorized assessment activities. Validate all findings before remediation decisions.', styles['BodyText'])]
    data = [['Module', 'Risk', 'Date']] + [[s.module, s.risk, s.created_at.strftime('%Y-%m-%d %H:%M')] for s in scans]
    table = Table(data, colWidths=[2.2*inch, 1.1*inch, 2.2*inch]); table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0b1f3a')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.25,colors.grey),('PADDING',(0,0),(-1,-1),6)]))
    story += [Spacer(1, .25*inch), Paragraph('Assessment Activity', styles['Heading2']), table]
    SimpleDocTemplate(str(path), pagesize=A4, title='CyberShield Assessment Report').build(story)
