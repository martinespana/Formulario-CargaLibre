"""CargaLibre: server-backed forms, individual links, private administration."""
import base64, hashlib, hmac, io, json, os, re, secrets, sqlite3, time, uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo
import click
from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from PIL import Image
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

DECLARATION = 'Declaro que soy la persona identificada en este formulario, que lo he diligenciado personalmente y que la información suministrada es veraz. Confirmo que he revisado su contenido y que la firma registrada corresponde a mi manifestación de aceptación.'
COMPANIES = 'COOPERATIVA CARGA LIBRE Y CARGA LIBRE S.A.S.'
POLICY = 'Autorizo a Cooperativa Carga Libre y Carga Libre S.A.S. a tratar los datos suministrados para la evaluación y vinculación de conductores terceros, verificación de referencias y seguridad de las operaciones de transporte. He podido consultar la política de tratamiento de datos y los canales para ejercer mis derechos.'
LABELS = {'nombre':'NOMBRES Y APELLIDOS','documento':'DOCUMENTO','tipoDocumento':'TIPO DE DOCUMENTO','telefono':'CELULAR DECLARADO (SIN VERIFICACIÓN TÉCNICA)','ciudad':'CIUDAD','direccion':'DIRECCIÓN','rol':'QUIEN DILIGENCIA','tramite':'TIPO DE REGISTRO','placa':'PLACA','modelo':'MODELO','tipoVehiculo':'TIPO DE VEHÍCULO','trailer':'PLACA TRÁILER','propio':'¿ES EL PROPIETARIO?','tenedor':'¿EXISTE OTRO TENEDOR?','propNombre':'PROPIETARIO','propTipoDocumento':'TIPO DE DOCUMENTO PROPIETARIO','propDocumento':'DOCUMENTO PROPIETARIO','propTelefono':'TELÉFONO PROPIETARIO','propCiudad':'CIUDAD PROPIETARIO','propDireccion':'DIRECCIÓN PROPIETARIO','tenNombre':'TENEDOR','tenDocumento':'DOCUMENTO TENEDOR','tenTelefono':'TELÉFONO TENEDOR','tenCiudad':'CIUDAD TENEDOR','tenDireccion':'DIRECCIÓN TENEDOR','contacto':'CONTACTO DE EMERGENCIA','parentesco':'PARENTESCO','contactoTel':'TELÉFONO DE EMERGENCIA','contacto2':'SEGUNDO CONTACTO','parentesco2':'PARENTESCO SEGUNDO CONTACTO','contacto2Tel':'TELÉFONO SEGUNDO CONTACTO','empresaA':'REFERENCIA A','empresaATel':'TELÉFONO REFERENCIA A','empresaB':'REFERENCIA B','empresaBTel':'TELÉFONO REFERENCIA B'}

def canonical(obj): return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def digest(value): return hashlib.sha256(value.encode() if isinstance(value,str) else value).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat()
def connect(path):
    db=sqlite3.connect(path,timeout=30,isolation_level=None);db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');return db

def create_app(test_config=None):
    app=Flask(__name__)
    app.config.update(DATA_DIR=os.environ.get('DATA_DIR','./data'),PRODUCTION=os.environ.get('APP_ENV')=='production',TESTING=False,MAX_CONTENT_LENGTH=700_000,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',PERMANENT_SESSION_LIFETIME=86400*7,POLICY_APPROVED=os.environ.get('POLICY_APPROVED')=='yes',POLICY_URL=os.environ.get('POLICY_URL','https://cargalibre.com.co/tratamiento-datos'),PUBLIC_URL=os.environ.get('PUBLIC_URL','http://127.0.0.1:8766'),TRUST_PROXY=os.environ.get('TRUST_PROXY')=='yes',SECRET_KEY=os.environ.get('SECRET_KEY'))
    if test_config: app.config.update(test_config)
    root=Path(app.config['DATA_DIR']).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    app.config['DB_PATH']=str(root/'cargalibre.sqlite3')
    if not app.config['SECRET_KEY']:
        if app.config['PRODUCTION']: raise RuntimeError('SECRET_KEY obligatorio en producción')
        secret_file=root/'session.key'
        if not secret_file.exists(): secret_file.write_text(secrets.token_hex(32));secret_file.chmod(0o600)
        app.config['SECRET_KEY']=secret_file.read_text().strip()
    app.config['SESSION_COOKIE_SECURE']=app.config['PRODUCTION']
    if app.config['PRODUCTION'] and len(app.config['SECRET_KEY'])<64:raise RuntimeError('SECRET_KEY debe tener al menos 64 caracteres aleatorios')
    if app.config['PRODUCTION'] and (not app.config['POLICY_APPROVED'] or not app.config['PUBLIC_URL'].startswith('https://')): raise RuntimeError('Se requieren HTTPS y POLICY_APPROVED=yes tras revisar la autorización y política')
    if app.config['TRUST_PROXY']:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app=ProxyFix(app.wsgi_app,x_for=1,x_proto=1,x_host=0,x_port=0,x_prefix=0)
    key_path=root/'signing.key'
    if not key_path.exists():
        key=Ed25519PrivateKey.generate();key_path.write_bytes(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()));key_path.chmod(0o600)
    key=Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    app.config['PUBLIC_KEY']=base64.b64encode(pub).decode()
    def sign(obj): return base64.b64encode(key.sign(canonical(obj))).decode()
    db=connect(app.config['DB_PATH'])
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS admin_sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),expires REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS invites(id TEXT PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,created_at TEXT NOT NULL,expires REAL NOT NULL,created_by INTEGER REFERENCES users(id),branch TEXT NOT NULL,dispatcher TEXT NOT NULL,expected_name TEXT NOT NULL,expected_document TEXT NOT NULL,expected_phone TEXT NOT NULL,used_record TEXT UNIQUE,revoked INTEGER NOT NULL DEFAULT 0,draft TEXT);
    CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,invite_id TEXT UNIQUE NOT NULL REFERENCES invites(id),created_at TEXT NOT NULL,name TEXT NOT NULL,document TEXT NOT NULL,plate TEXT NOT NULL,payload TEXT NOT NULL,payload_hash TEXT NOT NULL,seal TEXT NOT NULL,pdf BLOB NOT NULL,pdf_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,invite_id TEXT,event TEXT NOT NULL,created_at TEXT NOT NULL,ip TEXT NOT NULL,user_agent TEXT NOT NULL,actor TEXT NOT NULL,details TEXT NOT NULL,previous_hash TEXT NOT NULL,entry_hash TEXT NOT NULL,seal TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS attempts(bucket TEXT NOT NULL,at REAL NOT NULL);
    CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts(bucket,at);
    CREATE INDEX IF NOT EXISTS records_name ON records(name);
    CREATE INDEX IF NOT EXISTS records_plate ON records(plate);
    CREATE INDEX IF NOT EXISTS records_document ON records(document);
    CREATE TRIGGER IF NOT EXISTS immutable_records_update BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT,'El expediente es inmutable'); END;
    CREATE TRIGGER IF NOT EXISTS immutable_records_delete BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT,'El expediente es inmutable'); END;
    CREATE TRIGGER IF NOT EXISTS immutable_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'El historial es inmutable'); END;
    CREATE TRIGGER IF NOT EXISTS immutable_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'El historial es inmutable'); END;
    ''');db.close()
    def db():
        if 'db' not in g:g.db=connect(app.config['DB_PATH'])
        return g.db
    @app.teardown_appcontext
    def close_db(error=None):
        conn=g.pop('db',None)
        if conn:conn.close()
    def csrf():
        if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(32)
        return session['csrf']
    app.jinja_env.globals.update(csrf=csrf,companies=COMPANIES)
    @app.template_filter('colombia')
    def colombia(value):return datetime.fromisoformat(value).astimezone(ZoneInfo('America/Bogota')).strftime('%d/%m/%Y %H:%M:%S')
    @app.before_request
    def security():
        if request.method in ('POST','PUT','DELETE','PATCH'):
            supplied=request.headers.get('X-CSRF-Token') or request.form.get('csrf','')
            if not session.get('csrf') or not hmac.compare_digest(supplied,session['csrf']):abort(403,description='Sesión vencida. Recargue la página.')
    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Permissions-Policy':'camera=(), microphone=(), geolocation=()','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        if app.config['PRODUCTION']: response.headers['Strict-Transport-Security']='max-age=31536000'
        return response
    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(410)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def error(e):
        if request.path.startswith('/api/'):return jsonify(error=e.description),e.code
        return render_template('message.html',title='No se pudo continuar',message=e.description),e.code
    def audit(event,invite=None,actor=None,details=None):
        conn=db();own=not conn.in_transaction
        if own:conn.execute('BEGIN IMMEDIATE')
        try:
            prev=conn.execute('SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
            entry={'invite_id':invite,'event':event,'created_at':now(),'ip':request.remote_addr or '','user_agent':request.headers.get('User-Agent','')[:500],'actor':actor or 'conductor','details':details or {},'previous_hash':prev[0] if prev else '0'*64}
            eh=digest(canonical(entry))
            conn.execute('INSERT INTO audit(invite_id,event,created_at,ip,user_agent,actor,details,previous_hash,entry_hash,seal) VALUES(?,?,?,?,?,?,?,?,?,?)',(invite,event,entry['created_at'],entry['ip'],entry['user_agent'],entry['actor'],json.dumps(entry['details'],ensure_ascii=False),entry['previous_hash'],eh,sign(entry)))
            if own:conn.commit()
        except:
            if own:conn.rollback()
            raise
    def rate(bucket,limit,seconds):
        conn=db();conn.execute('BEGIN IMMEDIATE')
        conn.execute('DELETE FROM attempts WHERE at<?',(time.time()-86400,))
        count=conn.execute('SELECT count(*) FROM attempts WHERE bucket=? AND at>?',(bucket,time.time()-seconds)).fetchone()[0]
        if count>=limit:conn.commit();abort(429,description='Demasiados intentos. Intente más tarde.')
        conn.execute('INSERT INTO attempts VALUES(?,?)',(bucket,time.time()));conn.commit()
    def admin(view):
        @wraps(view)
        def wrapped(*args,**kwargs):
            token=session.get('admin','');u=db().execute('SELECT users.* FROM users JOIN admin_sessions ON user_id=users.id WHERE token_hash=? AND expires>? AND active=1',(digest(token),time.time())).fetchone()
            if not u:
                if request.path.startswith('/api/'):abort(403)
                return redirect(url_for('login'))
            g.user=u
            return view(*args,**kwargs)
        return wrapped
    def invite(active=True):
        row=db().execute('SELECT * FROM invites WHERE token_hash=?',(session.get('invite',''),)).fetchone()
        if not row:abort(403,description='Abra su enlace individual para continuar.')
        if row['revoked']:abort(410,description='Este enlace fue revocado. Contacte al despachador.')
        if active and (row['expires']<time.time() or row['used_record']):abort(410,description='El enlace venció o ya fue utilizado. Contacte al despachador.')
        return row
    @app.get('/')
    def home():return render_template('message.html',title='Registro de conductores CargaLibre',message='Solicite su enlace individual al despachador. Cada enlace permite finalizar un solo formulario.',admin_link=True)
    @app.route('/admin/login',methods=['GET','POST'])
    def login():
        message=None
        if request.method=='POST':
            user=request.form.get('username','').strip().lower()[:100]
            rate('login-ip:'+str(request.remote_addr),15,900);rate('login-user:'+user,10,900)
            row=db().execute('SELECT * FROM users WHERE username=? AND active=1',(user,)).fetchone()
            check=check_password_hash(row['password_hash'] if row else app.config['DUMMY_HASH'],request.form.get('password',''))
            if row and check:
                session.clear();session.permanent=True;token=secrets.token_urlsafe(32);session['admin']=token;csrf()
                db().execute('INSERT INTO admin_sessions VALUES(?,?,?)',(digest(token),row['id'],time.time()+28800));audit('ADMIN_LOGIN',actor=user);return redirect(url_for('dashboard'))
            audit('ADMIN_LOGIN_FAILED',actor='desconocido');message='Usuario o contraseña incorrectos.'
        return render_template('login.html',error=message)
    @app.post('/admin/logout')
    @admin
    def logout():
        db().execute('DELETE FROM admin_sessions WHERE token_hash=?',(digest(session.get('admin','')),));session.clear();return redirect(url_for('login'))
    @app.get('/admin')
    @admin
    def dashboard():
        q=request.args.get('q','').strip().upper()[:100];page=max(1,min(int(request.args.get('page','1')) if request.args.get('page','1').isdigit() else 1,100000))
        where="WHERE instr(name,?)>0 OR instr(document,?)>0 OR instr(plate,?)>0" if q else ''
        params=(q,q,q) if q else ()
        records=db().execute('SELECT id,created_at,name,document,plate FROM records '+where+' ORDER BY created_at DESC LIMIT 50 OFFSET ?',(*params,(page-1)*50)).fetchall()
        pending=db().execute('SELECT id,branch,dispatcher,expected_name,created_at,expires,revoked,used_record FROM invites ORDER BY created_at DESC LIMIT 30').fetchall()
        return render_template('admin.html',records=records,pending=pending,q=q,page=page,production=app.config['PRODUCTION'])
    @app.post('/admin/invites')
    @admin
    def new_invite():
        vals={k:request.form.get(k,'').strip().upper() for k in ('name','document','phone','branch','dispatcher')}
        if any(not x or len(x)>200 for x in vals.values()) or not re.fullmatch('[0-9]{10}',vals['phone']):abort(400,description='Complete los datos y un celular de 10 dígitos.')
        token=secrets.token_urlsafe(32);ident=str(uuid.uuid4());created=now();expires=time.time()+7*86400
        db().execute('INSERT INTO invites(id,token_hash,created_at,expires,created_by,branch,dispatcher,expected_name,expected_document,expected_phone) VALUES(?,?,?,?,?,?,?,?,?,?)',(ident,digest(token),created,expires,g.user['id'],vals['branch'],vals['dispatcher'],vals['name'],vals['document'],vals['phone']))
        audit('LINK_CREATED',ident,g.user['username'])
        return render_template('link.html',link=app.config['PUBLIC_URL'].rstrip('/')+'/f/'+token)
    @app.post('/admin/invites/<ident>/revoke')
    @admin
    def revoke(ident):
        db().execute('UPDATE invites SET revoked=1 WHERE id=? AND used_record IS NULL',(ident,));audit('LINK_REVOKED',ident,g.user['username']);return redirect(url_for('dashboard'))
    @app.get('/f/<token>')
    def open_form(token):
        if not re.fullmatch('[A-Za-z0-9_-]{40,60}',token):abort(404)
        hashed=digest(token);row=db().execute('SELECT * FROM invites WHERE token_hash=?',(hashed,)).fetchone()
        if not row:abort(404,description='Enlace no válido.')
        session['invite']=hashed;session.permanent=True;session.pop('receipt',None)
        row=invite();csrf();audit('LINK_OPENED',row['id'])
        # Remove the bearer token from browser address bar and subsequent requests.
        return redirect(url_for('form_page'))
    @app.get('/formulario')
    def form_page():invite();return render_template('form.html')
    @app.get('/api/context')
    def context():
        row=invite();return jsonify(csrf=csrf(),branch=row['branch'],dispatcher=row['dispatcher'],created_at=row['created_at'],server_time=now(),expected={'nombre':row['expected_name'],'documento':row['expected_document'],'telefono':row['expected_phone']},draft=json.loads(row['draft']) if row['draft'] else {},version=digest(canonical([DECLARATION,POLICY,app.config['POLICY_URL']])),declaration=DECLARATION,policy=POLICY,policy_url=app.config['POLICY_URL'],production=app.config['PRODUCTION'])
    @app.post('/api/draft')
    def draft():
        row=invite();raw=request.get_json(silent=True)
        if not isinstance(raw,dict):abort(400)
        clean={k:str(v).strip().upper()[:200] for k,v in raw.items() if k in LABELS and isinstance(v,(str,int))}
        db().execute('UPDATE invites SET draft=? WHERE id=? AND used_record IS NULL',(json.dumps(clean,ensure_ascii=False),row['id']))
        return jsonify(saved_at=now())
    def validate(raw,row):
        if not isinstance(raw,dict):abort(400,description='Datos inválidos.')
        data={k:str(v).strip().upper() for k,v in raw.items() if k in LABELS and isinstance(v,(str,int)) and not isinstance(v,bool)}
        if any(len(v)>200 or any(ord(c)<32 for c in v) for v in data.values()):abort(400,description='Hay campos demasiado largos o caracteres inválidos.')
        required=['nombre','tipoDocumento','documento','telefono','ciudad','direccion','rol','tramite','placa','modelo','tipoVehiculo','propio','tenedor','contacto','parentesco','contactoTel','empresaA','empresaATel','empresaB','empresaBTel']
        if data.get('propio')=='NO':required+=['propNombre','propTipoDocumento','propDocumento','propTelefono','propCiudad','propDireccion']
        else:
            for k in list(data):
                if k.startswith('prop') and k!='propio':data.pop(k)
        if data.get('tenedor')=='SÍ':required+=['tenNombre','tenDocumento','tenTelefono','tenCiudad','tenDireccion']
        else:
            for k in list(data):
                if k.startswith('ten') and k!='tenedor':data.pop(k)
        if any(data.get(k) for k in ['contacto2','parentesco2','contacto2Tel']):required+=['contacto2','parentesco2','contacto2Tel']
        if any(not data.get(k) for k in required):abort(400,description='Complete todos los campos obligatorios y los datos del segundo contacto si lo incluye.')
        enums={'rol':['CONDUCTOR','PROPIETARIO','TENEDOR'],'tramite':['NUEVO','ACTUALIZACIÓN'],'tipoVehiculo':['NHR','TURBO','SENCILLO','DOBLETROQUE','PATINETA','MULA'],'propio':['SÍ','NO'],'tenedor':['SÍ','NO'],'tipoDocumento':['CÉDULA DE CIUDADANÍA','CÉDULA DE EXTRANJERÍA','OTRO','NIT']}
        if any(data.get(k) not in opts for k,opts in enums.items()):abort(400,description='Selección no válida.')
        if data.get('propio')=='NO' and data.get('propTipoDocumento') not in ['NIT','CÉDULA DE CIUDADANÍA']:abort(400,description='Documento de propietario inválido.')
        if data['rol']=='PROPIETARIO' and data['tipoDocumento'] not in ['NIT','CÉDULA DE CIUDADANÍA']:abort(400,description='Documento de propietario inválido.')
        for k,v in data.items():
            if (k=='telefono' or k.endswith('Telefono') or k.endswith('Tel')) and v and not re.fullmatch('[0-9]{10}',v):abort(400,description='Cada teléfono debe tener exactamente 10 dígitos.')
        if not re.fullmatch('[A-Z]{3}[ -]?[0-9]{3}',data['placa']):abort(400,description='Placa no válida.')
        data['placa']=re.sub('[ -]','',data['placa'])
        if not data['modelo'].isdigit() or not 1950<=int(data['modelo'])<=datetime.now().year+1:abort(400,description='Modelo no válido.')
        if data['tipoVehiculo'] not in ['PATINETA','MULA']:data.pop('trailer',None)
        if data['documento']!=row['expected_document'] or data['telefono']!=row['expected_phone']:abort(400,description='Documento o celular no coincide con el enlace. Contacte al despachador.')
        if raw.get('declaration') is not True or raw.get('consent') is not True:abort(400,description='Debe aceptar la autorización y la declaración antes de firmar.')
        return data
    @app.post('/api/submit')
    def submit():
        row=invite(active=False)
        if row['used_record']:
            if session.get('receipt')==row['used_record']:return jsonify(receipt='/comprobante/'+row['used_record'],id=row['used_record'])
            abort(410,description='El enlace ya fue utilizado.')
        if row['expires']<time.time():abort(410)
        rate('submit:'+row['id'],20,3600)
        raw=request.get_json(silent=True);data=validate(raw,row)
        if raw.get('version')!=digest(canonical([DECLARATION,POLICY,app.config['POLICY_URL']])):abort(409,description='El texto del formulario cambió. Recargue y revíselo antes de firmar.')
        sig=raw.get('signature','')
        if not isinstance(sig,str) or not sig.startswith('data:image/png;base64,') or len(sig)>500000:abort(400,description='Firma inválida.')
        try:
            png=base64.b64decode(sig.split(',',1)[1],validate=True)
            with Image.open(io.BytesIO(png)) as image:
                if image.format!='PNG' or image.width>2000 or image.height>1000 or image.width<100 or image.height<50:raise ValueError()
                image.load()
                # Reject a blank canvas; a transparent background is composed onto white.
                bg=Image.new('RGBA',image.size,'white');bg.alpha_composite(image.convert('RGBA'));gray=bg.convert('L')
                if sum(gray.histogram()[:180])<30:raise ValueError()
                out=io.BytesIO();bg.convert('RGB').save(out,format='PNG');png=out.getvalue()
        except Exception:abort(400,description='Dibuje una firma válida en el recuadro.')
        ident='CL-'+uuid.uuid4().hex.upper();stamp=now()
        payload={'schema_version':1,'id':ident,'created_at':stamp,'companies':COMPANIES,'branch':row['branch'],'dispatcher':row['dispatcher'],'invite_id':row['id'],'expected_identity':{'name':row['expected_name'],'document':row['expected_document'],'phone':row['expected_phone']},'data':data,'authorization':{'version':'1','text':POLICY,'url':app.config['POLICY_URL'],'accepted':True},'declaration':{'version':'1','text':DECLARATION,'accepted':True},'evidence':{'ip':request.remote_addr or '','user_agent':request.headers.get('User-Agent','')[:500],'method':'ENLACE INDIVIDUAL Y DECLARACIÓN PERSONAL','phone_verified':False},'signature_png':base64.b64encode(png).decode()}
        pdf=make_pdf(payload,png);pdf_hash=digest(pdf);body_hash=digest(canonical(payload));manifest={'payload_hash':body_hash,'pdf_hash':pdf_hash,'id':ident};seal=sign(manifest)
        conn=db();conn.execute('BEGIN IMMEDIATE')
        try:
            current=conn.execute('SELECT used_record,revoked,expires FROM invites WHERE id=?',(row['id'],)).fetchone()
            if current['used_record'] or current['revoked'] or current['expires']<time.time():abort(409,description='El enlace ya no está disponible.')
            conn.execute('INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?,?,?)',(ident,row['id'],stamp,data['nombre'],data['documento'],data['placa'],canonical(payload).decode(),body_hash,seal,pdf,pdf_hash))
            conn.execute('UPDATE invites SET used_record=?,draft=NULL WHERE id=?',(ident,row['id']))
            audit('FORM_SIGNED_AND_SEALED',row['id'],details={'record_id':ident,'payload_hash':body_hash,'pdf_hash':pdf_hash})
            conn.commit()
        except:conn.rollback();raise
        session['receipt']=ident
        return jsonify(id=ident,receipt='/comprobante/'+ident)
    def accessible(ident):
        if session.get('receipt')!=ident:
            token=session.get('admin','')
            user=db().execute('SELECT users.id FROM users JOIN admin_sessions ON users.id=user_id WHERE token_hash=? AND expires>? AND active=1',(digest(token),time.time())).fetchone()
            if not user:abort(403,description='No tiene acceso a este comprobante.')
        row=db().execute('SELECT * FROM records WHERE id=?',(ident,)).fetchone()
        if not row:abort(404)
        try:
            payload=json.loads(row['payload']);manifest={'id':ident,'payload_hash':digest(canonical(payload)),'pdf_hash':digest(row['pdf'])}
            if manifest['payload_hash']!=row['payload_hash'] or manifest['pdf_hash']!=row['pdf_hash']:raise ValueError()
            key.public_key().verify(base64.b64decode(row['seal']),canonical(manifest))
        except Exception:abort(409,description='Falló la comprobación de integridad. Contacte al administrador.')
        return row,payload
    @app.get('/comprobante/<ident>')
    def receipt(ident):
        row,payload=accessible(ident)
        return render_template('receipt.html',record=row,payload=payload,labels=LABELS)
    @app.get('/comprobante/<ident>/pdf')
    def receipt_pdf(ident):
        row,payload=accessible(ident);return send_file(io.BytesIO(row['pdf']),mimetype='application/pdf',as_attachment=True,download_name=ident+'.pdf')
    @app.get('/admin/records/<ident>/evidence')
    @admin
    def evidence(ident):
        row,payload=accessible(ident);audit('EVIDENCE_EXPORTED',row['invite_id'],g.user['username'])
        envelope={'payload':payload,'payload_hash':row['payload_hash'],'pdf_hash':row['pdf_hash'],'seal':row['seal'],'public_key':app.config['PUBLIC_KEY']}
        return send_file(io.BytesIO(canonical(envelope)),mimetype='application/json',as_attachment=True,download_name=ident+'-evidencia.json')
    @app.get('/admin/records/<ident>/history')
    @admin
    def history(ident):
        row,payload=accessible(ident)
        from verify import check_database
        try:check_database(app.config['DB_PATH'],app.config['PUBLIC_KEY'])
        except Exception:abort(409,description='La integridad del historial no pudo verificarse.')
        events=db().execute('SELECT * FROM audit WHERE invite_id=? ORDER BY seq',(row['invite_id'],)).fetchall()
        return render_template('history.html',record=row,events=events)
    @app.get('/health')
    def health():db().execute('SELECT 1');return jsonify(status='ok')
    @app.cli.command('create-admin')
    @click.option('--username',prompt='Usuario administrador')
    @click.password_option(confirmation_prompt=True)
    def create_admin(username,password):
        if len(password)<14:raise click.ClickException('Use una contraseña de al menos 14 caracteres.')
        with app.app_context():db().execute('INSERT INTO users(username,password_hash) VALUES(?,?)',(username.strip().lower(),generate_password_hash(password)))
        click.echo('Administrador creado. La contraseña no se almacena en texto plano.')
    @app.cli.command('reset-password')
    @click.option('--username',prompt='Usuario administrador')
    @click.password_option(confirmation_prompt=True)
    def reset_password(username,password):
        if len(password)<14:raise click.ClickException('Use al menos 14 caracteres.')
        conn=db();conn.execute('BEGIN IMMEDIATE');row=conn.execute('SELECT id FROM users WHERE username=?',(username.strip().lower(),)).fetchone()
        if not row:conn.rollback();raise click.ClickException('Usuario no encontrado.')
        conn.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(password),row['id']));conn.execute('DELETE FROM admin_sessions WHERE user_id=?',(row['id'],));conn.commit();click.echo('Contraseña actualizada y sesiones cerradas.')
    app.config['DUMMY_HASH']=generate_password_hash(secrets.token_urlsafe(24))
    return app


def make_pdf(payload,png):
    out=io.BytesIO();c=canvas.Canvas(out,pagesize=A4);w,h=A4;y=h-45
    def text(line,bold=False):
        nonlocal y
        if y<65:c.showPage();y=h-45
        c.setFont('Helvetica-Bold' if bold else 'Helvetica',9)
        import textwrap
        for part in textwrap.wrap(str(line),95) or ['']:
            if y<65:c.showPage();y=h-45;c.setFont('Helvetica',9)
            c.drawString(40,y,part);y-=14
    logo=Path(__file__).parent/'static'/'logo.png'
    if logo.exists():c.drawImage(str(logo),40,y-45,width=85,height=55,preserveAspectRatio=True,mask='auto');y-=65
    text('COMPROBANTE DE DILIGENCIAMIENTO Y FIRMA',True);text(COMPANIES);text(payload['id']);text('FECHA DEL SERVIDOR: '+payload['created_at']);text('SUCURSAL: '+payload['branch']);text('DESPACHADOR: '+payload['dispatcher']);y-=10
    for k,label in LABELS.items():
        v=payload['data'].get(k)
        if v:text(label+': '+v)
    y-=10;text('AUTORIZACIÓN ACEPTADA',True);text(payload['authorization']['text']);text('POLÍTICA: '+payload['authorization']['url']);text('DECLARACIÓN ACEPTADA',True);text(DECLARATION)
    text('IP DE ENVÍO: '+payload['evidence']['ip']);text('CELULAR DECLARADO; SIN VERIFICACIÓN TÉCNICA DE TITULARIDAD.')
    if y<170:c.showPage();y=h-45
    c.drawImage(ImageReader(io.BytesIO(png)),40,y-75,width=250,height=75,preserveAspectRatio=True);y-=90
    text('FIRMA REGISTRADA POR QUIEN DILIGENCIA.');text('ORIGINAL CONSERVADO EN CARGALIBRE; INTEGRIDAD VERIFICABLE.')
    c.save();return out.getvalue()

if __name__=='__main__':create_app().run(host='127.0.0.1',port=8766,debug=False)
