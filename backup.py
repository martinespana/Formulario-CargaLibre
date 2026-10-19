"""Consistent encrypted local backup and safe restore."""
import argparse,base64,io,json,os,sqlite3,tarfile,tempfile,time
from pathlib import Path
from datetime import datetime,timezone
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from verify import check_database

FILES={'cargalibre.sqlite3','signing.key','session.key'}
KEEP_DAYS=14
def prune(folder,days=KEEP_DAYS):
    # Only after a successful new backup, so the folder is never left empty.
    limit=time.time()-days*86400
    for old in Path(folder).glob('cargalibre-*.enc'):
        if old.stat().st_mtime<limit:old.unlink()
def backup(data_dir,encryption_key,destination):
    root=Path(data_dir);fernet=Fernet(encryption_key)
    with tempfile.TemporaryDirectory() as temp:
        snap=Path(temp)/'cargalibre.sqlite3'
        src=sqlite3.connect(root/'cargalibre.sqlite3');dst=sqlite3.connect(snap);src.backup(dst);dst.close();src.close()
        private=Ed25519PrivateKey.from_private_bytes((root/'signing.key').read_bytes())
        pub=base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        status=check_database(snap,pub)
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w:gz') as tar:
            tar.add(snap,arcname='cargalibre.sqlite3')
            for name in ['signing.key','session.key']:
                if (root/name).exists():tar.add(root/name,arcname=name)
        encrypted=fernet.encrypt(buf.getvalue());path=Path(destination);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(encrypted);path.chmod(0o600)
        return status

def restore(archive,encryption_key,dest,public_key):
    target=Path(dest)
    if target.exists() and any(target.iterdir()):raise ValueError('El destino de restauración debe estar vacío')
    plain=Fernet(encryption_key).decrypt(Path(archive).read_bytes())
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz') as tar:
            for member in tar.getmembers():
                if member.name not in FILES or not member.isfile() or member.size>2_000_000_000:raise ValueError('Contenido no permitido')
                (root/member.name).write_bytes(tar.extractfile(member).read())
        if not (root/'cargalibre.sqlite3').exists() or not (root/'signing.key').exists():raise ValueError('Copia incompleta')
        status=check_database(root/'cargalibre.sqlite3',public_key)
        restored=Ed25519PrivateKey.from_private_bytes((root/'signing.key').read_bytes()).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        if base64.b64encode(restored).decode()!=public_key:raise ValueError('Clave de firma no coincide')
        # Invalidate sessions and legacy bearer access on a disaster recovery.
        conn=sqlite3.connect(root/'cargalibre.sqlite3');conn.execute('DELETE FROM admin_sessions');conn.commit();conn.close()
        target.mkdir(parents=True,exist_ok=True,mode=0o700)
        for item in root.iterdir():
            if item.name in FILES:(target/item.name).write_bytes(item.read_bytes());(target/item.name).chmod(0o600)
        return status

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--data-dir',default=os.environ.get('DATA_DIR','./data'));p.add_argument('--dest');p.add_argument('--restore');p.add_argument('--public-key');a=p.parse_args()
    encryption=os.environ.get('BACKUP_ENCRYPTION_KEY')
    if not encryption:raise SystemExit('Falta BACKUP_ENCRYPTION_KEY; consérvela fuera de la VPS')
    if a.restore:
        if not a.public_key:p.error('--public-key obligatorio para restaurar')
        print(restore(a.restore,encryption,a.data_dir,Path(a.public_key).read_text().strip()))
    else:
        dest=a.dest or str(Path(a.data_dir)/'backups'/('cargalibre-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'.enc'))
        print(backup(a.data_dir,encryption,dest));prune(Path(dest).parent)
