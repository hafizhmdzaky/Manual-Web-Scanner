# app.py - Main Flask Application
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import threading
import requests
from scanner.crawler import WebCrawler
from scanner.vulnerability_manager import VulnerabilityManager
from config import Config
from werkzeug.utils import secure_filename
import os
from flask import send_from_directory

app = Flask(__name__)
app.config.from_object(Config)

# Database setup
db = SQLAlchemy(app)


# Database Models
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    total_pages = db.Column(db.Integer, default=0)
    total_forms = db.Column(db.Integer, default=0)
    vulnerability_count = db.Column(db.Integer, default=0)
    scan_settings = db.Column(db.Text)  # JSON string of settings

    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    vuln_type = db.Column(db.String(50), nullable=False)
    subtype = db.Column(db.String(100))
    severity = db.Column(db.String(20), nullable=False)
    severity_score = db.Column(db.Float)
    url = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10))
    payload = db.Column(db.Text)
    parameter = db.Column(db.String(200))
    evidence = db.Column(db.Text)
    description = db.Column(db.Text)
    impact = db.Column(db.Text)
    remediation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ScanProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    current_step = db.Column(db.String(100))
    total_steps = db.Column(db.Integer, default=7)
    current_step_number = db.Column(db.Integer, default=1)
    message = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


# Global dictionary to store active scans
active_scans = {}


# Routes
@app.route('/')
def dashboard():
    """Main dashboard"""
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()

    # Calculate statistics
    total_scans = Scan.query.count()
    total_vulnerabilities = Vulnerability.query.count()

    # Vulnerability statistics
    vuln_stats = {
        'Critical': Vulnerability.query.filter_by(severity='Critical').count(),
        'High': Vulnerability.query.filter_by(severity='High').count(),
        'Medium': Vulnerability.query.filter_by(severity='Medium').count(),
        'Low': Vulnerability.query.filter_by(severity='Low').count()
    }

    # Recent vulnerabilities
    recent_vulns = Vulnerability.query.order_by(Vulnerability.created_at.desc()).limit(5).all()

    return render_template('dashboard.html',
                           recent_scans=recent_scans,
                           total_scans=total_scans,
                           total_vulnerabilities=total_vulnerabilities,
                           vuln_stats=vuln_stats,
                           recent_vulns=recent_vulns)


@app.route('/new-scan')
def new_scan():
    """New scan configuration page"""
    return render_template('new_scan.html')


@app.route('/start-scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    target_url = request.form.get('target_url')
    max_pages = int(request.form.get('max_pages', 50))
    selected_scanners = request.form.getlist('scanners')

    if not target_url:
        flash('Target URL is required', 'error')
        return redirect(url_for('new_scan'))

    # Create scan record
    scan_settings = {
        'max_pages': max_pages,
        'selected_scanners': selected_scanners
    }

    scan = Scan(
        target_url=target_url,
        status='pending',
        scan_settings=json.dumps(scan_settings)
    )

    db.session.add(scan)
    db.session.commit()

    # Start scan in background thread
    thread = threading.Thread(target=run_scan_background, args=(scan.id,))
    thread.daemon = True
    thread.start()

    flash(f'Scan started for {target_url}', 'success')
    return redirect(url_for('scan_detail', scan_id=scan.id))


@app.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    """Scan detail page"""
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).order_by(Vulnerability.severity_score.desc()).all()

    # Group vulnerabilities by type
    vuln_by_type = {}
    for vuln in vulnerabilities:
        if vuln.vuln_type not in vuln_by_type:
            vuln_by_type[vuln.vuln_type] = []
        vuln_by_type[vuln.vuln_type].append(vuln)

    return render_template('scan_detail.html',
                           scan=scan,
                           vulnerabilities=vulnerabilities,
                           vuln_by_type=vuln_by_type)


@app.route('/api/scan-progress/<int:scan_id>')
def scan_progress_api(scan_id):
    """API endpoint for scan progress"""
    scan = Scan.query.get_or_404(scan_id)
    progress = ScanProgress.query.filter_by(scan_id=scan_id).order_by(ScanProgress.updated_at.desc()).first()

    response = {
        'scan_id': scan_id,
        'status': scan.status,
        'progress': {
            'current_step': progress.current_step if progress else 'Initializing',
            'current_step_number': progress.current_step_number if progress else 1,
            'total_steps': progress.total_steps if progress else 7,
            'message': progress.message if progress else 'Starting scan...',
            'percentage': ((progress.current_step_number / progress.total_steps) * 100) if progress else 0
        },
        'vulnerability_count': scan.vulnerability_count or 0
    }

    return jsonify(response)


@app.route('/reports')
def reports():
    """Reports page"""
    scans = Scan.query.filter_by(status='completed').order_by(Scan.completed_at.desc()).all()
    return render_template('reports.html', scans=scans)


@app.route('/export-scan/<int:scan_id>/<format>')
def export_scan(scan_id, format):
    """Export scan results"""
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()

    if format == 'json':
        return export_json(scan, vulnerabilities)
    elif format == 'csv':
        return export_csv(scan, vulnerabilities)
    else:
        flash('Unsupported export format', 'error')
        return redirect(url_for('scan_detail', scan_id=scan_id))


def export_json(scan, vulnerabilities):
    """Export scan results as JSON"""
    data = {
        'scan_info': {
            'id': scan.id,
            'target_url': scan.target_url,
            'created_at': scan.created_at.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'total_pages': scan.total_pages,
            'total_forms': scan.total_forms,
            'vulnerability_count': scan.vulnerability_count
        },
        'vulnerabilities': []
    }

    for vuln in vulnerabilities:
        data['vulnerabilities'].append({
            'type': vuln.vuln_type,
            'subtype': vuln.subtype,
            'severity': vuln.severity,
            'severity_score': vuln.severity_score,
            'url': vuln.url,
            'method': vuln.method,
            'payload': vuln.payload,
            'parameter': vuln.parameter,
            'evidence': vuln.evidence,
            'description': vuln.description,
            'impact': vuln.impact,
            'remediation': vuln.remediation,
            'found_at': vuln.created_at.isoformat()
        })

    filename = f"scan_{scan.id}_report.json"

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(data, f, indent=2)
        temp_path = f.name

    return send_file(temp_path, as_attachment=True, download_name=filename)


def export_csv(scan, vulnerabilities):
    """Export scan results as CSV"""
    import csv
    import tempfile

    filename = f"scan_{scan.id}_report.csv"

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Vulnerability Type', 'Subtype', 'Severity', 'Severity Score',
            'URL', 'Method', 'Parameter', 'Payload', 'Evidence',
            'Description', 'Impact', 'Remediation', 'Found At'
        ])

        for vuln in vulnerabilities:
            writer.writerow([
                vuln.vuln_type, vuln.subtype, vuln.severity, vuln.severity_score,
                vuln.url, vuln.method, vuln.parameter, vuln.payload, vuln.evidence,
                vuln.description, vuln.impact, vuln.remediation, vuln.created_at
            ])

        temp_path = f.name

    return send_file(temp_path, as_attachment=True, download_name=filename)


# Add these routes after your existing routes, before run_scan_background function

@app.route('/payloads')
def payload_management():
    """Payload management page"""
    # Get existing payload files
    payload_dir = os.path.join(app.root_path, 'payloads')
    if not os.path.exists(payload_dir):
        os.makedirs(payload_dir)

    payload_files = {}
    vuln_types = ['xss', 'sqli', 'csrf', 'xxe', 'lfi', 'rce', 'auth', 'custom']

    for vuln_type in vuln_types:
        type_dir = os.path.join(payload_dir, vuln_type)
        if os.path.exists(type_dir):
            files = [f for f in os.listdir(type_dir) if f.endswith('.txt')]
            payload_files[vuln_type] = []
            for file in files:
                file_path = os.path.join(type_dir, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        payload_count = len([line for line in lines if line.strip() and not line.startswith('#')])

                    payload_files[vuln_type].append({
                        'filename': file,
                        'payload_count': payload_count,
                        'size': os.path.getsize(file_path)
                    })
                except Exception as e:
                    print(f"Error reading {file}: {e}")
        else:
            payload_files[vuln_type] = []

    return render_template('payload_management.html', payload_files=payload_files)


@app.route('/upload-payload', methods=['POST'])
def upload_payload():
    """Upload custom payload file"""
    if 'payload_file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('payload_management'))

    file = request.files['payload_file']
    vuln_type = request.form.get('vuln_type')

    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('payload_management'))

    if not vuln_type:
        flash('Vulnerability type is required', 'error')
        return redirect(url_for('payload_management'))

    if file and file.filename.endswith('.txt'):
        filename = secure_filename(file.filename)

        # Create directory if it doesn't exist
        payload_dir = os.path.join(app.root_path, 'payloads', vuln_type)
        if not os.path.exists(payload_dir):
            os.makedirs(payload_dir)

        # Save file
        file_path = os.path.join(payload_dir, filename)
        file.save(file_path)

        # Validate payload file format
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                valid_payloads = [line.strip() for line in lines if line.strip() and not line.startswith('#')]

            flash(f'Payload file uploaded successfully! Found {len(valid_payloads)} valid payloads.', 'success')
        except Exception as e:
            flash(f'Error reading payload file: {str(e)}', 'error')
            # Remove invalid file
            if os.path.exists(file_path):
                os.remove(file_path)
    else:
        flash('Only .txt files are allowed', 'error')

    return redirect(url_for('payload_management'))


@app.route('/delete-payload/<vuln_type>/<filename>')
def delete_payload(vuln_type, filename):
    """Delete a payload file"""
    filename = secure_filename(filename)
    file_path = os.path.join(app.root_path, 'payloads', vuln_type, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'Payload file {filename} deleted successfully', 'success')
    else:
        flash('Payload file not found', 'error')

    return redirect(url_for('payload_management'))


@app.route('/download-payload/<vuln_type>/<filename>')
def download_payload(vuln_type, filename):
    """Download a payload file"""
    payload_dir = os.path.join(app.root_path, 'payloads', vuln_type)
    return send_from_directory(payload_dir, filename, as_attachment=True)


@app.route('/create-sample-payloads')
def create_sample_payloads():
    """Create sample payload files"""
    payload_dir = os.path.join(app.root_path, 'payloads')

    # Sample payloads for different vulnerability types
    sample_payloads = {
        'xss': [
            '# XSS Payload Collection',
            '# Basic XSS payloads',
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '"><script>alert("XSS")</script>',
            '<iframe src=javascript:alert("XSS")></iframe>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            # Advanced XSS
            '<script>confirm("XSS")</script>',
            '<img src="x" onerror="alert(\\"XSS\\")">',
            '<svg/onload=alert("XSS")>',
            '"-alert("XSS")-"',
            '\';alert("XSS");//',
            '</script><script>alert("XSS")</script>'
        ],
        'sqli': [
            '# SQL Injection Payload Collection',
            '# Error-based payloads',
            "'",
            '"',
            "')",
            "';",
            "' OR '1'='1",
            '" OR "1"="1',

            '" OR 1=1--',
            "') OR ('1'='1",
            '") OR ("1"="1',
            # Union-based
            "' UNION SELECT NULL--",
            '" UNION SELECT NULL--',
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT user(),version(),database()--",
            # Time-based
            "'; WAITFOR DELAY '00:00:05'--",
            '"; WAITFOR DELAY \'00:00:05\'--',
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            "'; SELECT SLEEP(5)--",
            "'; pg_sleep(5)--"
        ]
    }

    for vuln_type, payloads in sample_payloads.items():
        type_dir = os.path.join(payload_dir, vuln_type)
        if not os.path.exists(type_dir):
            os.makedirs(type_dir)

        sample_file = os.path.join(type_dir, f'{vuln_type}_sample.txt')
        if not os.path.exists(sample_file):
            with open(sample_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(payloads))

    flash('Sample payload files created successfully!', 'success')
    return redirect(url_for('payload_management'))

def run_scan_background(scan_id):
    """Background function to run vulnerability scan"""
    try:
        with app.app_context():
            scan = Scan.query.get(scan_id)
            scan.status = 'running'
            db.session.commit()

            # Parse scan settings
            settings = json.loads(scan.scan_settings)
            max_pages = settings.get('max_pages', 50)
            selected_scanners = settings.get('selected_scanners', ['xss', 'sqli', 'csrf'])

            # Update progress
            update_progress(scan_id, 'Initializing crawler', 1, 'Setting up web crawler...')

            # Initialize session and crawler
            session = requests.Session()
            session.verify = False  # For testing
            session.headers.update({
                'User-Agent': 'WebVulnScanner/1.0'
            })

            # Step 1: Crawl target
            update_progress(scan_id, 'Crawling target', 2, f'Discovering pages and forms...')
            crawler = WebCrawler(scan.target_url, max_pages=max_pages)
            crawl_results = crawler.crawl()

            # Update scan with crawl results
            scan.total_pages = len(crawl_results['visited_urls'])
            scan.total_forms = len(crawl_results['forms'])
            db.session.commit()

            # Step 2: Run vulnerability scans
            update_progress(scan_id, 'Running vulnerability scans', 3, 'Testing for security vulnerabilities...')
            vuln_manager = VulnerabilityManager(session)

            # Run selected scans
            step_num = 4
            for scanner_name in selected_scanners:
                scanner_display = {
                    'xss': 'Cross-Site Scripting',
                    'sqli': 'SQL Injection',
                    'csrf': 'CSRF',
                    'auth': 'Authentication',
                    'sensitive': 'Sensitive Data',
                    'xxe': 'XXE',
                    'access': 'Access Control'
                }.get(scanner_name, scanner_name.upper())

                update_progress(scan_id, f'Testing {scanner_display}', step_num, f'Running {scanner_display} tests...')

                vulnerabilities = vuln_manager.scanners[scanner_name].scan(crawl_results)

                # Save vulnerabilities to database
                for vuln_data in vulnerabilities:
                    vuln = Vulnerability(
                        scan_id=scan_id,
                        vuln_type=vuln_data['type'],
                        subtype=vuln_data['subtype'],
                        severity=vuln_data['severity'],
                        severity_score=vuln_data.get('severity_score', 5.0),
                        url=vuln_data['url'],
                        method=vuln_data['method'],
                        payload=vuln_data['payload'],
                        parameter=str(vuln_data['parameter']),
                        evidence=vuln_data['evidence'],
                        description=vuln_data['description'],
                        impact=vuln_data['impact'],
                        remediation=vuln_data['remediation']
                    )
                    db.session.add(vuln)

                step_num += 1
                db.session.commit()

            # Final step: Complete scan
            update_progress(scan_id, 'Finalizing results', 7, 'Generating final report...')

            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            scan.vulnerability_count = Vulnerability.query.filter_by(scan_id=scan_id).count()
            db.session.commit()

            update_progress(scan_id, 'Completed', 7,
                            f'Scan completed. Found {scan.vulnerability_count} vulnerabilities.')

    except Exception as e:
        with app.app_context():
            scan = Scan.query.get(scan_id)
            scan.status = 'failed'
            db.session.commit()
            update_progress(scan_id, 'Failed', 7, f'Scan failed: {str(e)}')


def update_progress(scan_id, step, step_number, message):
    """Update scan progress"""
    with app.app_context():
        # Remove old progress entries for this scan
        ScanProgress.query.filter_by(scan_id=scan_id).delete()

        # Add new progress entry
        progress = ScanProgress(
            scan_id=scan_id,
            current_step=step,
            current_step_number=step_number,
            message=message
        )
        db.session.add(progress)
        db.session.commit()


def update_progress(scan_id, step, step_number, message):
    """Update scan progress"""
    with app.app_context():
        # Remove old progress entries for this scan
        ScanProgress.query.filter_by(scan_id=scan_id).delete()

        # Add new progress entry
        progress = ScanProgress(
            scan_id=scan_id,
            current_step=step,
            current_step_number=step_number,
            message=message
        )
        db.session.add(progress)
        db.session.commit()


def init_db():
    """Initialize database tables"""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")


if __name__ == '__main__':
    # Initialize database before starting the app
    init_db()

    print("Starting Web Application Vulnerability Scanner...")
    print("Access the web interface at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")

    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
