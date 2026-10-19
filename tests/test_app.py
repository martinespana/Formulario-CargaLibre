import base64,copy,io,json,os,re,sqlite3,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import create_app
from backup import backup,prune,restore
from verify import check_database,check_envelope
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash
from PIL import Image,ImageDraw
class PlatformTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  self.app=create_app({'TESTING':True,'DATA_DIR':str(self.root/'data'),'SECRET_KEY':'unit-test-secret-only','PUBLIC_URL':'https://example.test'})
  self.admin=self.app.test_client();self.driver=self.app.test_client()
  conn=sqlite3.connect(self.app.config['DB_PATH']);conn.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',('tester',generate_password_hash('Test-password-only-123')));conn.commit();conn.close()
  self.admin.get('/admin/login')
  with self.admin.session_transaction() as s:self.csrf=s['csrf']
  self.assertEqual(self.admin.post('/admin/login',data={'csrf':self.csrf,'username':'tester','password':'Test-password-only-123'}).status_code,302)
  with self.admin.session_transaction() as s:self.csrf=s['csrf']
 def tearDown(self):self.temp.cleanup()
 def link(self):
  r=self.admin.post('/admin/invites',data={'csrf':self.csrf,'name':'conductor de prueba','document':'PRUEBA001','phone':'0000000000','branch':'bogota','dispatcher':'despachador ficticio'})
  self.assertEqual(r.status_code,200)
  return re.search(r'https://example.test(/f/[A-Za-z0-9_-]+)',r.text).group(1)
 def setup_driver(self):
  link=self.link();self.assertEqual(self.driver.get(link).status_code,302);ctx=self.driver.get('/api/context').json;self.token=ctx['csrf'];self.version=ctx['version'];return link
 def data(self):
  image=Image.new('RGB',(1000,360),'white');ImageDraw.Draw(image).line([(50,100),(500,200),(850,50)],fill='black',width=5);out=io.BytesIO();image.save(out,format='PNG')
  return {'nombre':'conductor de prueba','documento':'PRUEBA001','telefono':'0000000000','tipoDocumento':'Otro','ciudad':'bogotá','direccion':'prueba','rol':'Conductor','tramite':'Nuevo','placa':'zzz000','modelo':'2020','tipoVehiculo':'NHR','trailer':'DO NOT KEEP','propio':'Sí','tenedor':'No','contacto':'ficticio','parentesco':'hermano','contactoTel':'0000000000','empresaA':'prueba a','empresaATel':'0000000000','empresaB':'prueba b','empresaBTel':'0000000000','version':self.version,'consent':True,'declaration':True,'signature':'data:image/png;base64,'+base64.b64encode(out.getvalue()).decode()}
 def submit(self,data=None):return self.driver.post('/api/submit',json=data or self.data(),headers={'X-CSRF-Token':self.token,'User-Agent':'Automated fictitious test','X-Forwarded-For':'203.0.113.2'})
 def test_full_flow_integrity_filters_and_immutability(self):
  link=self.setup_driver();self.assertEqual(self.driver.post('/api/draft',json={'nombre':'prueba'},headers={'X-CSRF-Token':self.token}).status_code,200)
  res=self.submit();self.assertEqual(res.status_code,200,res.text);ident=res.json['id']
  self.assertEqual(self.submit().json['id'],ident)
  self.assertIn('SU FORMATO HA SIDO DILIGENCIADO',self.driver.get(res.json['receipt']).text)
  self.assertEqual(self.driver.get(res.json['receipt']+'/pdf').mimetype,'application/pdf')
  stranger=self.app.test_client();self.assertEqual(stranger.get(res.json['receipt']).status_code,403);self.assertEqual(stranger.get(link).status_code,410)
  for q in ['ZZZ000','CONDUCTOR','PRUEBA001']:self.assertIn(ident,self.admin.get('/admin?q='+q).text)
  self.assertNotIn(ident,self.admin.get('/admin?q=NOCOINCIDE').text)
  envelope=self.admin.get('/admin/records/'+ident+'/evidence').json
  self.assertEqual(envelope['payload']['data']['nombre'],'CONDUCTOR DE PRUEBA');self.assertNotIn('trailer',envelope['payload']['data']);self.assertFalse(envelope['payload']['evidence']['phone_verified']);self.assertEqual(envelope['payload']['evidence']['ip'],'127.0.0.1')
  self.assertNotIn('/f/',json.dumps(envelope))
  pdf=self.driver.get(res.json['receipt']+'/pdf').data;check_envelope(envelope,self.app.config['PUBLIC_KEY'],pdf)
  bad=copy.deepcopy(envelope);bad['payload']['data']['nombre']='ALTERADO'
  with self.assertRaises(Exception):check_envelope(bad,self.app.config['PUBLIC_KEY'],pdf)
  with self.assertRaises(Exception):check_envelope(envelope,self.app.config['PUBLIC_KEY'],pdf+b'alterado')
  conn=sqlite3.connect(self.app.config['DB_PATH'])
  with self.assertRaises(sqlite3.IntegrityError):conn.execute('UPDATE records SET name=? WHERE id=?',('ALTERADO',ident))
  conn.rollback()
  with self.assertRaises(sqlite3.IntegrityError):conn.execute('DELETE FROM records')
  conn.rollback();conn.close()
  self.assertEqual(check_database(self.app.config['DB_PATH'],self.app.config['PUBLIC_KEY'])['records'],1)
 def test_validation_and_csrf(self):
  self.setup_driver()
  for key,value in [('telefono','123'),('contactoTel','12345abc90'),('declaration',False),('consent',False),('modelo','1000'),('propio','INVALID')]:
   d=self.data();d[key]=value;self.assertEqual(self.submit(d).status_code,400,(key,self.submit(d).text))
  d=self.data();d['contacto2']='ALGUIEN';self.assertEqual(self.submit(d).status_code,400)
  d=self.data();d['signature']='data:image/png;base64,'+base64.b64encode(b'not png').decode();self.assertEqual(self.submit(d).status_code,400)
  self.assertEqual(self.driver.post('/api/submit',json=self.data()).status_code,403)
 def test_revocation_expiry_and_admin_protection(self):
  self.assertEqual(self.app.test_client().get('/admin').status_code,302)
  self.setup_driver();conn=sqlite3.connect(self.app.config['DB_PATH']);ident=conn.execute('SELECT id FROM invites LIMIT 1').fetchone()[0];conn.close()
  self.assertEqual(self.admin.post('/admin/invites/'+ident+'/revoke',data={'csrf':self.csrf}).status_code,302);self.assertEqual(self.submit().status_code,410)
  self.setup_driver();conn=sqlite3.connect(self.app.config['DB_PATH']);conn.execute('UPDATE invites SET expires=0');conn.commit();conn.close();self.assertEqual(self.submit().status_code,410)
 def test_backup_restore_is_real_and_encrypted(self):
  self.setup_driver();self.assertEqual(self.submit().status_code,200)
  key=Fernet.generate_key();file=self.root/'backup.enc';backup(self.root/'data',key,file)
  self.assertNotIn(b'CONDUCTOR',file.read_bytes());out=self.root/'restored';status=restore(file,key,out,self.app.config['PUBLIC_KEY']);self.assertEqual(status['records'],1)
  self.assertEqual(check_database(out/'cargalibre.sqlite3',self.app.config['PUBLIC_KEY'])['records'],1)
  with self.assertRaises(ValueError):restore(file,key,out,self.app.config['PUBLIC_KEY'])
  with self.assertRaises(Exception):restore(file,Fernet.generate_key(),self.root/'wrong-key',self.app.config['PUBLIC_KEY'])
 def test_prune_keeps_recent_backups(self):
  old=self.root/'cargalibre-old.enc';new=self.root/'cargalibre-new.enc';other=self.root/'nota.txt'
  for f in (old,new,other):f.write_bytes(b'x')
  os.utime(old,(0,0));os.utime(other,(0,0));prune(self.root)
  self.assertFalse(old.exists());self.assertTrue(new.exists());self.assertTrue(other.exists())
 def test_fail_closed_production(self):
  with self.assertRaises(RuntimeError):create_app({'DATA_DIR':str(self.root/'prod'),'PRODUCTION':True,'SECRET_KEY':'secret','POLICY_APPROVED':False})
if __name__=='__main__':unittest.main()
