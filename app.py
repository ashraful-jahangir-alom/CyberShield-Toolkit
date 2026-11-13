import csv, io, json, logging, os, time
from datetime import datetime
from functools import wraps
from pathlib import Path
from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from config import Config
from forms.login_form import LoginForm
from models import db
from models.user import User
from models.scan import Scan
from models.report import Report
from modules import dns_lookup, network, ports, vulnerability, webscan, whois_lookup
from modules.encrypt import decrypt, encrypt, generate_key, valid_key
from modules.hash_tools import hashes
from modules.password import generate_password
from modules.report import build_report
from modules.ssl_checker import check_ssl
from modules.utils import authorization_notice, normalize_target
def create_app():
    BASE_DIR = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / 'templates'),
        static_folder=str(BASE_DIR / 'static')
    )
    app.config.from_object(Config)
    for folder in (Config.UPLOAD_FOLDER, Config.REPORT_FOLDER):
        try:
            Path(folder).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    db.init_app(app); CSRFProtect(app)
    limiter = Limiter(get_remote_address, app=app, default_limits=['200 per day', '50 per hour'], storage_uri='memory://')
    login_manager = LoginManager(app); login_manager.login_view = 'login'; login_manager.login_message_category = 'warning'
    
    from config import is_serverless
    if is_serverless():
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    else:
        try:
            Path('logs').mkdir(exist_ok=True)
            logging.basicConfig(filename=Path('logs') / 'cybershield.log', level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        except Exception:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    @login_manager.user_loader
    def load_user(user_id): return db.session.get(User, int(user_id))
    with app.app_context():
        try:
            db.create_all()
            if not User.query.filter_by(username=os.getenv('ADMIN_USERNAME', 'admin')).first():
                admin = User(username=os.getenv('ADMIN_USERNAME', 'admin')); admin.set_password(os.getenv('ADMIN_PASSWORD', 'ChangeMe123!'))
                db.session.add(admin); db.session.commit()
                app.logger.warning('Default administrator created. Change ADMIN_PASSWORD immediately.')
        except Exception as exc:
            app.logger.error('Database initialization warning: %s', exc)
    def log_scan(target, module, result, risk='LOW', started=None):
        record = Scan(user_id=current_user.id, target=target, module=module, result=json.dumps(result, default=str), risk=risk, duration=round(time.time() - started, 2) if started else 0)
        db.session.add(record); db.session.commit(); app.logger.info('%s scan on %s by %s', module, target, current_user.username)
        return record
    def authorized_scan(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if request.method == 'POST' and request.form.get('authorized') != 'yes':
                flash('Confirm that you own or are authorized to assess this target.', 'danger'); return redirect(request.url)
            return fn(*args, **kwargs)
        return wrapped
    @app.route('/')
    def index(): return redirect(url_for('dashboard' if current_user.is_authenticated else 'login'))
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit('10 per minute')
    def login():
        if current_user.is_authenticated: return redirect(url_for('dashboard'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data.strip()).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember.data); return redirect(request.args.get('next') or url_for('dashboard'))
            flash('Invalid username or password.', 'danger')
        return render_template('login.html', form=form)
    @app.route('/logout')
    @login_required
    def logout(): logout_user(); flash('You have been signed out.', 'info'); return redirect(url_for('login'))
    @app.route('/dashboard')
    @login_required
    def dashboard():
        scans = Scan.query.order_by(Scan.created_at.desc()).limit(8).all()
        stats = {'total': Scan.query.count(), 'ports': sum(1 for s in Scan.query.filter_by(module='Port Scanner').all() if 'open' in s.result), 'high': Scan.query.filter_by(risk='HIGH').count(), 'reports': Report.query.count()}
        return render_template('dashboard.html', stats=stats, scans=scans)
    @app.route('/information', methods=['GET','POST'])
    @login_required
    @authorized_scan
    def information():
        result = None
        if request.method == 'POST':
            started=time.time()
            try:
                target=normalize_target(request.form['target']); result={'whois':whois_lookup.lookup(target),'dns':dns_lookup.lookup(target)}
                try: result['ssl']=check_ssl(target)
                except Exception as e: result['ssl']={'note':str(e)}
                log_scan(target,'Information Gathering',result,started=started)
            except Exception as e: flash(str(e),'danger')
        return render_template('information.html', result=result, notice=authorization_notice())
    @app.route('/ports', methods=['GET','POST'])
    @login_required
    @authorized_scan
    def port_scanner():
        result=None
        if request.method=='POST':
            started=time.time()
            try:
                target=normalize_target(request.form['target']); result=ports.scan(target); log_scan(target,'Port Scanner',result,'MEDIUM' if any(x['risk']=='MEDIUM' for x in result) else 'LOW',started)
            except Exception as e: flash(str(e),'danger')
        return render_template('ports.html', result=result, notice=authorization_notice())
    @app.route('/network', methods=['GET','POST'])
    @login_required
    @authorized_scan
    def network_discovery():
        result=None
        if request.method=='POST':
            started=time.time()
            try:
                target=request.form['target'].strip(); result=network.arp_scan(target); log_scan(target,'Network Discovery',result,started=started)
            except Exception as e: flash(str(e),'danger')
        return render_template('network.html', result=result, notice=authorization_notice())
    @app.route('/webscan', methods=['GET','POST'])
    @login_required
    @authorized_scan
    def website_scan():
        result=None
        if request.method=='POST':
            started=time.time()
            try:
                target=normalize_target(request.form['target']); result=webscan.scan(target); log_scan(target,'Website Scanner',result,'MEDIUM' if result['missing_headers'] else 'LOW',started)
            except Exception as e: flash(str(e),'danger')
        return render_template('webscan.html', result=result, notice=authorization_notice())
    @app.route('/vulnerability', methods=['GET','POST'])
    @login_required
    @authorized_scan
    def vulnerability_scan():
        result=None
        if request.method=='POST':
            started=time.time()
            try:
                target=normalize_target(request.form['target']); result=vulnerability.scan(target); risk='HIGH' if any(x['risk']=='HIGH' for x in result['findings']) else 'MEDIUM' if result['findings'] else 'LOW'; log_scan(target,'Vulnerability Scanner',result,risk,started)
            except Exception as e: flash(str(e),'danger')
        return render_template('vulnerability.html', result=result, notice=authorization_notice())
    @app.route('/password', methods=['GET','POST'])
    @login_required
    def password_tool():
        result=None
        if request.method=='POST':
            try: result=generate_password(int(request.form.get('length',20)), bool(request.form.get('upper')),bool(request.form.get('lower')),bool(request.form.get('numbers')),bool(request.form.get('symbols')),bool(request.form.get('avoid')))
            except Exception as e: flash(str(e),'danger')
        return render_template('password.html', result=result)
    @app.route('/hash', methods=['GET','POST'])
    @login_required
    def hash_tool(): return render_template('hash.html', result=hashes(request.form['text']) if request.method=='POST' and request.form.get('text') else None)
    @app.route('/encrypt', methods=['GET','POST'])
    @login_required
    def encryption():
        if request.method=='POST':
            file=request.files.get('file'); key=request.form.get('key','').encode(); action=request.form.get('action')
            if action=='key': return render_template('encryption.html', generated_key=generate_key().decode())
            elif not file or not file.filename: flash('Choose a file.','danger')
            elif not valid_key(key): flash('Enter a valid base64-encoded AES-256 key. Use "Generate AES-256 Key" if needed.','danger')
            else:
                try:
                    if action not in ('encrypt', 'decrypt'):
                        raise ValueError('Choose Encrypt or Decrypt.')
                    data=encrypt(file.read(), key) if action=='encrypt' else decrypt(file.read(), key)
                    original_name = secure_filename(file.filename) or 'cybershield-file'
                    name=original_name + ('.encrypted' if action=='encrypt' else '.decrypted')
                    return send_file(io.BytesIO(data), as_attachment=True, download_name=name)
                except Exception as e: flash(f'Processing failed: {e}','danger')
        return render_template('encryption.html', generated_key=None)
    @app.route('/reports', methods=['GET','POST'])
    @login_required
    def reports():
        if request.method=='POST':
            target=request.form.get('target','Authorized Assessment').strip()[:255]; scans=Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(30).all(); score=max(0,100-10*sum(s.risk=='MEDIUM' for s in scans)-25*sum(s.risk=='HIGH' for s in scans)); filename=f'report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.pdf'; build_report(Config.REPORT_FOLDER/filename,target,scans,score); db.session.add(Report(user_id=current_user.id,target=target,filename=filename,score=score)); db.session.commit(); flash('PDF report generated.','success')
        return render_template('reports.html', reports=Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).all())
    @app.route('/reports/<int:report_id>/download')
    @login_required
    def download_report(report_id):
        report=Report.query.get_or_404(report_id)
        if report.user_id != current_user.id: abort(403)
        return send_file(Config.REPORT_FOLDER/report.filename, as_attachment=True)
    @app.route('/logs')
    @login_required
    def logs():
        query=Scan.query.filter_by(user_id=current_user.id)
        term=request.args.get('q','').strip()
        if term: query=query.filter(Scan.target.contains(term) | Scan.module.contains(term))
        return render_template('logs.html', scans=query.order_by(Scan.created_at.desc()).all())
    @app.route('/logs/export')
    @login_required
    def export_logs():
        output=io.StringIO(); writer=csv.writer(output); writer.writerow(['Date','Target','Module','Risk','Duration'])
        for s in Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()): writer.writerow([s.created_at,s.target,s.module,s.risk,s.duration])
        return send_file(io.BytesIO(output.getvalue().encode()),mimetype='text/csv',as_attachment=True,download_name='cybershield_logs.csv')
    @app.route('/settings', methods=['GET','POST'])
    @login_required
    def settings():
        if request.method=='POST': flash('Preferences are stored in this browser for this starter release.','info')
        return render_template('settings.html')
    return app
app = create_app()
if __name__ == '__main__': app.run(host='127.0.0.1', port=5000, debug=True)
