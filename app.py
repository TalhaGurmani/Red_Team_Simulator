from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import sqlite3
import json
import random
import datetime
import markdown2
from pathlib import Path
import networkx as nx
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'dev-secret-key')
CORS(app)

DATABASE = 'simulator.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            os TEXT NOT NULL,
            open_ports TEXT,
            vulnerabilities TEXT,
            criticality INTEGER DEFAULT 1,
            compromised INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            seed INTEGER,
            status TEXT DEFAULT 'pending',
            initial_host_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            turn_number INTEGER,
            phase TEXT,
            source_host_id INTEGER,
            target_host_id INTEGER,
            technique TEXT,
            mitre_id TEXT,
            success INTEGER,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE,
            name TEXT,
            description TEXT,
            exploitability REAL,
            os_affected TEXT,
            ports_affected TEXT
        )
    ''')
    
    conn.commit()
    
    cursor.execute('SELECT COUNT(*) as count FROM vulnerabilities')
    if cursor.fetchone()['count'] == 0:
        seed_vulnerabilities(conn)
    
    conn.close()

def seed_vulnerabilities(conn):
    vulns = [
        ('CVE-2021-44228', 'Log4Shell', 'Remote code execution in Log4j', 9.8, 'Linux,Windows', '8080,9200,443'),
        ('CVE-2017-0144', 'EternalBlue', 'SMB remote code execution', 9.3, 'Windows', '445'),
        ('CVE-2014-0160', 'Heartbleed', 'OpenSSL memory disclosure', 7.5, 'Linux,Windows', '443'),
        ('CVE-2019-0708', 'BlueKeep', 'RDP remote code execution', 9.8, 'Windows', '3389'),
        ('CVE-2021-26855', 'ProxyLogon', 'Microsoft Exchange SSRF', 9.1, 'Windows', '443,80'),
        ('CVE-2018-7600', 'Drupalgeddon2', 'Drupal RCE', 9.8, 'Linux', '80,443'),
        ('CVE-2020-1472', 'Zerologon', 'Netlogon privilege escalation', 10.0, 'Windows', '445'),
        ('CVE-2012-1823', 'PHP-CGI RCE', 'PHP CGI argument injection', 7.5, 'Linux,Windows', '80,443'),
        ('CVE-2015-1427', 'Elasticsearch RCE', 'Groovy sandbox bypass', 8.8, 'Linux', '9200,9300'),
        ('CVE-2019-11510', 'Pulse Secure VPN', 'Arbitrary file reading', 10.0, 'Linux', '443'),
    ]
    
    cursor = conn.cursor()
    for vuln in vulns:
        cursor.execute('''
            INSERT OR IGNORE INTO vulnerabilities 
            (cve_id, name, description, exploitability, os_affected, ports_affected)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', vuln)
    conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM hosts ORDER BY created_at DESC')
    hosts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    for host in hosts:
        host['open_ports'] = json.loads(host['open_ports']) if host['open_ports'] else []
        host['vulnerabilities'] = json.loads(host['vulnerabilities']) if host['vulnerabilities'] else []
    
    return jsonify(hosts)

@app.route('/api/hosts', methods=['POST'])
def create_host():
    data = request.json
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO hosts (name, ip_address, os, open_ports, vulnerabilities, criticality)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            data['name'],
            data['ip_address'],
            data['os'],
            json.dumps(data.get('open_ports', [])),
            json.dumps(data.get('vulnerabilities', [])),
            data.get('criticality', 1)
        ))
        conn.commit()
        host_id = cursor.lastrowid
        conn.close()
        return jsonify({'id': host_id, 'message': 'Host created successfully'}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'IP address already exists'}), 400

@app.route('/api/hosts/<int:host_id>', methods=['PUT'])
def update_host(host_id):
    data = request.json
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE hosts 
        SET name=?, ip_address=?, os=?, open_ports=?, vulnerabilities=?, criticality=?
        WHERE id=?
    ''', (
        data['name'],
        data['ip_address'],
        data['os'],
        json.dumps(data.get('open_ports', [])),
        json.dumps(data.get('vulnerabilities', [])),
        data.get('criticality', 1),
        host_id
    ))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Host updated successfully'})

@app.route('/api/hosts/<int:host_id>', methods=['DELETE'])
def delete_host(host_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM hosts WHERE id=?', (host_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Host deleted successfully'})

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vulnerabilities')
    vulns = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(vulns)

@app.route('/api/campaigns', methods=['GET'])
def get_campaigns():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM campaigns ORDER BY created_at DESC')
    campaigns = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(campaigns)

@app.route('/api/campaigns', methods=['POST'])
def create_campaign():
    data = request.json
    conn = get_db()
    cursor = conn.cursor()
    
    seed = data.get('seed') or random.randint(1000, 9999)
    
    cursor.execute('''
        INSERT INTO campaigns (name, description, seed, initial_host_id, status)
        VALUES (?, ?, ?, ?, 'pending')
    ''', (
        data['name'],
        data.get('description', ''),
        seed,
        data.get('initial_host_id')
    ))
    conn.commit()
    campaign_id = cursor.lastrowid
    conn.close()
    
    return jsonify({'id': campaign_id, 'seed': seed}), 201

@app.route('/api/campaigns/<int:campaign_id>/execute', methods=['POST'])
def execute_campaign(campaign_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM campaigns WHERE id=?', (campaign_id,))
    campaign = dict(cursor.fetchone())
    
    cursor.execute('SELECT * FROM hosts')
    all_hosts = [dict(row) for row in cursor.fetchall()]
    
    for host in all_hosts:
        host['open_ports'] = json.loads(host['open_ports']) if host['open_ports'] else []
        host['vulnerabilities'] = json.loads(host['vulnerabilities']) if host['vulnerabilities'] else []
    
    cursor.execute('SELECT * FROM vulnerabilities')
    all_vulns = {row['cve_id']: dict(row) for row in cursor.fetchall()}
    
    cursor.execute('DELETE FROM attack_logs WHERE campaign_id=?', (campaign_id,))
    conn.commit()
    
    results = run_simulation(campaign, all_hosts, all_vulns, conn)
    
    cursor.execute('''
        UPDATE campaigns 
        SET status='completed', completed_at=CURRENT_TIMESTAMP
        WHERE id=?
    ''', (campaign_id,))
    conn.commit()
    conn.close()
    
    return jsonify(results)

def run_simulation(campaign, hosts, vulnerabilities, conn):
    random.seed(campaign['seed'])
    cursor = conn.cursor()
    
    compromised_hosts = set()
    turn_number = 0
    logs = []
    
    initial_host_id = campaign.get('initial_host_id')
    if initial_host_id:
        initial_host = next((h for h in hosts if h['id'] == initial_host_id), None)
    else:
        initial_host = random.choice(hosts)
    
    compromised_hosts.add(initial_host['id'])
    
    log_attack(cursor, campaign['id'], turn_number, 'Initial Access', None, initial_host['id'],
               'External Remote Services', 'T1133', 1, 
               f"Initial foothold established on {initial_host['name']} ({initial_host['ip_address']})")
    
    logs.append({
        'turn': turn_number,
        'phase': 'Initial Access',
        'target': initial_host['name'],
        'success': True
    })
    
    max_turns = 20
    for turn in range(1, max_turns):
        turn_number = turn
        
        if turn <= 5:
            phase = 'Reconnaissance'
            perform_reconnaissance(cursor, campaign['id'], turn_number, hosts, compromised_hosts, logs)
        elif turn <= 12:
            phase = 'Exploitation'
            new_compromises = perform_exploitation(cursor, campaign['id'], turn_number, hosts, 
                                                   vulnerabilities, compromised_hosts, logs)
            if not new_compromises:
                break
        else:
            phase = 'Lateral Movement'
            new_compromises = perform_lateral_movement(cursor, campaign['id'], turn_number, hosts, 
                                                       compromised_hosts, logs)
            if not new_compromises:
                break
        
        if len(compromised_hosts) >= len(hosts):
            break
    
    conn.commit()
    
    return {
        'turns': turn_number,
        'compromised': len(compromised_hosts),
        'total_hosts': len(hosts),
        'logs': logs
    }

def perform_reconnaissance(cursor, campaign_id, turn, hosts, compromised_hosts, logs):
    techniques = [
        ('Network Service Scanning', 'T1046'),
        ('Network Sniffing', 'T1040'),
        ('System Information Discovery', 'T1082'),
        ('Remote System Discovery', 'T1018')
    ]
    
    for comp_id in list(compromised_hosts)[:2]:
        comp_host = next(h for h in hosts if h['id'] == comp_id)
        technique, mitre = random.choice(techniques)
        
        targets = [h for h in hosts if h['id'] not in compromised_hosts][:3]
        for target in targets:
            success = random.random() > 0.2
            details = f"Scanned {target['name']} from {comp_host['name']} - discovered {len(target['open_ports'])} open ports"
            
            log_attack(cursor, campaign_id, turn, 'Reconnaissance', comp_id, target['id'],
                      technique, mitre, success, details)
            
            if success:
                logs.append({
                    'turn': turn,
                    'phase': 'Reconnaissance',
                    'source': comp_host['name'],
                    'target': target['name'],
                    'technique': technique,
                    'success': True
                })

def perform_exploitation(cursor, campaign_id, turn, hosts, vulnerabilities, compromised_hosts, logs):
    new_compromises = []
    
    for comp_id in list(compromised_hosts):
        comp_host = next(h for h in hosts if h['id'] == comp_id)
        
        targets = [h for h in hosts if h['id'] not in compromised_hosts]
        if not targets:
            continue
        
        target = random.choice(targets[:5])
        
        if target['vulnerabilities']:
            vuln_cve = random.choice(target['vulnerabilities'])
            vuln = vulnerabilities.get(vuln_cve, {})
            exploitability = vuln.get('exploitability', 5.0)
            
            success_chance = (exploitability / 10.0) * 0.7 + random.random() * 0.3
            success = random.random() < success_chance
            
            if success:
                compromised_hosts.add(target['id'])
                new_compromises.append(target['id'])
                details = f"Successfully exploited {vuln.get('name', vuln_cve)} on {target['name']}"
                
                log_attack(cursor, campaign_id, turn, 'Exploitation', comp_id, target['id'],
                          'Exploit Public-Facing Application', 'T1190', 1, details)
                
                logs.append({
                    'turn': turn,
                    'phase': 'Exploitation',
                    'source': comp_host['name'],
                    'target': target['name'],
                    'technique': vuln.get('name', 'Exploitation'),
                    'success': True
                })
            else:
                details = f"Failed to exploit {vuln.get('name', vuln_cve)} on {target['name']}"
                log_attack(cursor, campaign_id, turn, 'Exploitation', comp_id, target['id'],
                          'Exploit Public-Facing Application', 'T1190', 0, details)
        
        if random.random() > 0.5:
            break
    
    return new_compromises

def perform_lateral_movement(cursor, campaign_id, turn, hosts, compromised_hosts, logs):
    new_compromises = []
    
    techniques = [
        ('Remote Services: SMB/Windows Admin Shares', 'T1021.002'),
        ('Remote Services: SSH', 'T1021.004'),
        ('Exploitation of Remote Services', 'T1210'),
        ('Pass the Hash', 'T1550.002')
    ]
    
    for comp_id in list(compromised_hosts):
        comp_host = next(h for h in hosts if h['id'] == comp_id)
        
        targets = [h for h in hosts if h['id'] not in compromised_hosts]
        if not targets:
            continue
        
        target = random.choice(targets[:3])
        technique, mitre = random.choice(techniques)
        
        success = random.random() > 0.4
        
        if success:
            compromised_hosts.add(target['id'])
            new_compromises.append(target['id'])
            details = f"Lateral movement from {comp_host['name']} to {target['name']} using {technique}"
            
            log_attack(cursor, campaign_id, turn, 'Lateral Movement', comp_id, target['id'],
                      technique, mitre, 1, details)
            
            logs.append({
                'turn': turn,
                'phase': 'Lateral Movement',
                'source': comp_host['name'],
                'target': target['name'],
                'technique': technique,
                'success': True
            })
        else:
            details = f"Failed lateral movement attempt from {comp_host['name']} to {target['name']}"
            log_attack(cursor, campaign_id, turn, 'Lateral Movement', comp_id, target['id'],
                      technique, mitre, 0, details)
        
        if random.random() > 0.6:
            break
    
    return new_compromises

def log_attack(cursor, campaign_id, turn, phase, source_id, target_id, technique, mitre, success, details):
    cursor.execute('''
        INSERT INTO attack_logs 
        (campaign_id, turn_number, phase, source_host_id, target_host_id, technique, mitre_id, success, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (campaign_id, turn, phase, source_id, target_id, technique, mitre, success, details))

@app.route('/api/campaigns/<int:campaign_id>/logs', methods=['GET'])
def get_campaign_logs(campaign_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT al.*, 
               sh.name as source_name, sh.ip_address as source_ip,
               th.name as target_name, th.ip_address as target_ip
        FROM attack_logs al
        LEFT JOIN hosts sh ON al.source_host_id = sh.id
        LEFT JOIN hosts th ON al.target_host_id = th.id
        WHERE al.campaign_id = ?
        ORDER BY al.turn_number, al.timestamp
    ''', (campaign_id,))
    
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(logs)

@app.route('/api/campaigns/<int:campaign_id>/report', methods=['GET'])
def generate_report(campaign_id):
    report_format = request.args.get('format', 'pdf')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM campaigns WHERE id=?', (campaign_id,))
    campaign = dict(cursor.fetchone())
    
    cursor.execute('''
        SELECT al.*, 
               sh.name as source_name, th.name as target_name
        FROM attack_logs al
        LEFT JOIN hosts sh ON al.source_host_id = sh.id
        LEFT JOIN hosts th ON al.target_host_id = th.id
        WHERE al.campaign_id = ?
        ORDER BY al.turn_number
    ''', (campaign_id,))
    logs = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute('SELECT DISTINCT target_host_id FROM attack_logs WHERE campaign_id=? AND success=1', 
                   (campaign_id,))
    compromised_count = len(cursor.fetchall())
    
    cursor.execute('SELECT COUNT(*) as total FROM hosts')
    total_hosts = cursor.fetchone()['total']
    
    conn.close()
    
    report_path = Path('reports')
    report_path.mkdir(exist_ok=True)
    
    if report_format == 'pdf':
        filename = f"campaign_{campaign_id}_report.pdf"
        filepath = report_path / filename
        generate_pdf_report(campaign, logs, compromised_count, total_hosts, filepath)
        return send_file(filepath, as_attachment=True, download_name=filename)
    else:
        report_md = generate_markdown_report(campaign, logs, compromised_count, total_hosts)
        filename = f"campaign_{campaign_id}_report.md"
        filepath = report_path / filename
        with open(filepath, 'w') as f:
            f.write(report_md)
        return send_file(filepath, as_attachment=True, download_name=filename)

def generate_pdf_report(campaign, logs, compromised, total, filepath):
    doc = SimpleDocTemplate(str(filepath), pagesize=letter,
                           rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=18)
    
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#E94560'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#1A1A2E'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#16213E'),
        spaceAfter=6,
        spaceBefore=6,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#1A1A2E'),
        alignment=TA_JUSTIFY
    )
    
    logo_path = Path('static/logo.png')
    if logo_path.exists():
        img = Image(str(logo_path), width=2*inch, height=1.5*inch)
        story.append(img)
        story.append(Spacer(1, 12))
    
    story.append(Paragraph("Red Team Campaign Report", title_style))
    story.append(Spacer(1, 12))
    
    campaign_info = [
        ['Campaign Name:', campaign['name']],
        ['Campaign ID:', str(campaign['id'])],
        ['Seed:', str(campaign['seed'])],
        ['Status:', campaign['status']],
        ['Generated:', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
    ]
    
    info_table = Table(campaign_info, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F5F5F5')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1A1A2E')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Spacer(1, 6))
    
    summary_text = f"""This report details a simulated red team campaign targeting a virtual network environment. 
    The simulation used deterministic algorithms with seed {campaign['seed']} to ensure reproducible results 
    for educational and training purposes."""
    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 12))
    
    success_rate = int(sum(1 for log in logs if log['success'])/len(logs)*100) if logs else 0
    compromise_rate = int(compromised/total*100) if total > 0 else 0
    
    key_findings = [
        ['Metric', 'Value'],
        ['Hosts Compromised', f'{compromised} / {total} ({compromise_rate}%)'],
        ['Attack Phases', str(len(set(log['phase'] for log in logs)))],
        ['Total Attack Actions', str(len(logs))],
        ['Success Rate', f'{success_rate}%']
    ]
    
    findings_table = Table(key_findings, colWidths=[3*inch, 3*inch])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E94560')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1A1A2E')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Attack Timeline", heading_style))
    story.append(Spacer(1, 6))
    
    timeline_data = [['Turn', 'Phase', 'Technique', 'Status', 'Source → Target']]
    for log in logs[:25]:
        status = '✓ SUCCESS' if log['success'] else '✗ FAILED'
        source = log['source_name'] or 'External'
        target = log['target_name'] or 'Unknown'
        timeline_data.append([
            str(log['turn_number']),
            log['phase'][:15],
            f"{log['technique'][:25]}",
            status,
            f"{source[:12]} → {target[:12]}"
        ])
    
    timeline_table = Table(timeline_data, colWidths=[0.5*inch, 1.2*inch, 1.8*inch, 0.8*inch, 2.2*inch])
    timeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F3460')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F5F5')]),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1A1A2E')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(timeline_table)
    story.append(PageBreak())
    
    story.append(Paragraph("MITRE ATT&CK Techniques Observed", heading_style))
    story.append(Spacer(1, 6))
    
    mitre_techniques = {}
    for log in logs:
        if log['mitre_id'] not in mitre_techniques:
            mitre_techniques[log['mitre_id']] = {
                'technique': log['technique'],
                'count': 0,
                'success': 0
            }
        mitre_techniques[log['mitre_id']]['count'] += 1
        if log['success']:
            mitre_techniques[log['mitre_id']]['success'] += 1
    
    mitre_data = [['MITRE ID', 'Technique', 'Uses', 'Success Rate']]
    for mitre_id, data in sorted(mitre_techniques.items()):
        success_rate = int(data['success']/data['count']*100) if data['count'] > 0 else 0
        mitre_data.append([
            mitre_id,
            data['technique'][:35],
            str(data['count']),
            f"{success_rate}%"
        ])
    
    mitre_table = Table(mitre_data, colWidths=[1*inch, 3*inch, 0.7*inch, 1*inch])
    mitre_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213E')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (2, 0), (3, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F5F5')]),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1A1A2E')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(mitre_table)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("Remediation Recommendations", heading_style))
    story.append(Spacer(1, 6))
    
    story.append(Paragraph("Critical Actions", subheading_style))
    critical_actions = [
        "Patch Vulnerabilities: Immediately update systems with known CVEs exploited during the simulation",
        "Network Segmentation: Implement VLANs and firewall rules to limit lateral movement",
        "Access Controls: Enforce principle of least privilege and multi-factor authentication",
        "Monitoring: Deploy EDR solutions and enable logging for attack technique detection"
    ]
    
    for action in critical_actions:
        story.append(Paragraph(f"• {action}", normal_style))
        story.append(Spacer(1, 4))
    
    story.append(Spacer(1, 8))
    story.append(Paragraph("Strategic Improvements", subheading_style))
    strategic = [
        "Conduct regular vulnerability assessments and penetration testing",
        "Implement network intrusion detection systems (NIDS)",
        "Establish incident response procedures and playbooks",
        "Train staff on security awareness and social engineering tactics",
        "Enable security information and event management (SIEM) for correlation"
    ]
    
    for item in strategic:
        story.append(Paragraph(f"• {item}", normal_style))
        story.append(Spacer(1, 4))
    
    story.append(Spacer(1, 20))
    
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#666666'),
        alignment=TA_CENTER,
        fontName='Helvetica-Oblique'
    )
    
    story.append(Paragraph("Disclaimer", subheading_style))
    disclaimer_text = """This is a simulated educational exercise. No real network scanning, exploitation, 
    or attacks were performed. All results are generated using deterministic algorithms for training purposes."""
    story.append(Paragraph(disclaimer_text, disclaimer_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Report Generated by Red Team Campaign Simulator", disclaimer_style))
    
    doc.build(story)

def generate_markdown_report(campaign, logs, compromised, total):
    report = f"""# Red Team Campaign Report
## Campaign: {campaign['name']}

**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Campaign ID:** {campaign['id']}  
**Seed:** {campaign['seed']}  
**Status:** {campaign['status']}

---

## Executive Summary

This report details a simulated red team campaign targeting a virtual network environment. The simulation used deterministic algorithms with seed `{campaign['seed']}` to ensure reproducible results for educational and training purposes.

### Key Findings

- **Hosts Compromised:** {compromised} / {total} ({int(compromised/total*100) if total > 0 else 0}%)
- **Attack Phases:** {len(set(log['phase'] for log in logs))}
- **Total Attack Actions:** {len(logs)}
- **Success Rate:** {int(sum(1 for log in logs if log['success'])/len(logs)*100) if logs else 0}%

---

## Attack Timeline

"""
    
    for i, log in enumerate(logs[:30], 1):
        status = "✓ SUCCESS" if log['success'] else "✗ FAILED"
        source = log['source_name'] or "External"
        target = log['target_name'] or "Unknown"
        
        report += f"""### Turn {log['turn_number']} - {log['phase']}
**{status}** | **Technique:** {log['technique']} ({log['mitre_id']})  
**Source:** {source} → **Target:** {target}  
**Details:** {log['details']}

"""
    
    report += """---

## MITRE ATT&CK Techniques Observed

"""
    
    mitre_techniques = {}
    for log in logs:
        if log['mitre_id'] not in mitre_techniques:
            mitre_techniques[log['mitre_id']] = {
                'technique': log['technique'],
                'count': 0,
                'success': 0
            }
        mitre_techniques[log['mitre_id']]['count'] += 1
        if log['success']:
            mitre_techniques[log['mitre_id']]['success'] += 1
    
    for mitre_id, data in sorted(mitre_techniques.items()):
        success_rate = int(data['success']/data['count']*100) if data['count'] > 0 else 0
        report += f"- **{mitre_id}** - {data['technique']} (Used {data['count']}x, {success_rate}% success)\n"
    
    report += """

---

## Remediation Recommendations

### Critical Actions

1. **Patch Vulnerabilities:** Immediately update systems with known CVEs exploited during the simulation
2. **Network Segmentation:** Implement VLANs and firewall rules to limit lateral movement
3. **Access Controls:** Enforce principle of least privilege and multi-factor authentication
4. **Monitoring:** Deploy EDR solutions and enable logging for attack technique detection

### Strategic Improvements

- Conduct regular vulnerability assessments and penetration testing
- Implement network intrusion detection systems (NIDS)
- Establish incident response procedures and playbooks
- Train staff on security awareness and social engineering tactics
- Enable security information and event management (SIEM) for correlation

### MITRE ATT&CK Mitigations

Review MITRE ATT&CK framework mitigations for each technique observed in this campaign. Prioritize controls that address multiple techniques simultaneously.

---

## Disclaimer

This is a simulated educational exercise. No real network scanning, exploitation, or attacks were performed. All results are generated using deterministic algorithms for training purposes.

**Report Generated by Red Team Campaign Simulator**
"""
    
    return report

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
