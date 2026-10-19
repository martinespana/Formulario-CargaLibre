"""Verify exported evidence against a separately retained trusted public key."""
import argparse,base64,hashlib,json,sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canonical(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def check_envelope(envelope,public_key,pdf=None):
    payload_hash=hashlib.sha256(canonical(envelope['payload'])).hexdigest()
    if payload_hash!=envelope['payload_hash']:raise ValueError('El contenido fue modificado')
    if pdf is not None and hashlib.sha256(pdf).hexdigest()!=envelope['pdf_hash']:raise ValueError('El PDF fue modificado')
    manifest={'id':envelope['payload']['id'],'payload_hash':payload_hash,'pdf_hash':envelope['pdf_hash']}
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key,validate=True)).verify(base64.b64decode(envelope['seal'],validate=True),canonical(manifest))

def check_database(path,public_key):
    conn=sqlite3.connect(path);conn.row_factory=sqlite3.Row
    if conn.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Base de datos dañada')
    count=0
    for r in conn.execute('SELECT * FROM records'):
        check_envelope({'payload':json.loads(r['payload']),'payload_hash':r['payload_hash'],'pdf_hash':r['pdf_hash'],'seal':r['seal']},public_key,r['pdf']);count+=1
    previous='0'*64;events=0;pub=Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
    for r in conn.execute('SELECT * FROM audit ORDER BY seq'):
        entry={k:r[k] for k in ['invite_id','event','created_at','ip','user_agent','actor','previous_hash']};entry['details']=json.loads(r['details'])
        if r['previous_hash']!=previous or hashlib.sha256(canonical(entry)).hexdigest()!=r['entry_hash']:raise ValueError('Cadena de eventos alterada')
        pub.verify(base64.b64decode(r['seal']),canonical(entry));previous=r['entry_hash'];events+=1
    conn.close();return {'records':count,'events':events,'last_event_hash':previous}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--public-key',required=True,help='Clave pública de confianza conservada fuera de la VPS');p.add_argument('--database');p.add_argument('--evidence');p.add_argument('--pdf');a=p.parse_args()
    public=Path(a.public_key).read_text().strip()
    if a.database:print(check_database(a.database,public))
    elif a.evidence:check_envelope(json.loads(Path(a.evidence).read_text()),public,Path(a.pdf).read_bytes() if a.pdf else None);print('Integridad y sello correctos')
    else:p.error('Indique --database o --evidence')
