# CargaLibre · Plataforma de conductores

Aplicación de servidor con formulario móvil, enlaces individuales de un solo uso, acceso privado de administración, base de datos SQLite, PDF conservado en servidor, sellos Ed25519 e historial con IP. No depende de SMS ni de Meta.

## Qué significa la evidencia

Se conserva la declaración aceptada, autorización y su versión, respuestas normalizadas, firma dibujada, hora UTC del servidor, IP observada, navegador e identificador interno del enlace. El celular se declara; no se verifica su titularidad. La IP tampoco identifica por sí sola a una persona. El enlace puede ser reenviado: debe entregarse individualmente por el canal habitual del despachador.

Un expediente finalizado no tiene rutas de edición o borrado. Disparadores de base de datos bloquean UPDATE/DELETE. Cada JSON y PDF tiene huella SHA-256 y un sello Ed25519 que se verifica antes de entregarlo. El PDF descargado se puede alterar con herramientas externas, pero dejaría de coincidir con el original y fallaría su verificación. El administrador funcional no puede modificar el expediente. Una persona con acceso raíz a la VPS sí puede atacar archivos y claves: para evidencia resistente a ese riesgo conserve la clave pública y copias fuera de la VPS. El sello del servidor no es un certificado de firma digital emitido por una entidad de certificación.

## Arranque local

Python 3.12. Dentro de esta carpeta:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
export DATA_DIR=./data
.venv/bin/flask --app 'app:create_app' create-admin
.venv/bin/flask --app 'app:create_app' run --host 127.0.0.1 --port 8766
```

Cree su usuario con contraseña de al menos 14 caracteres. No existe usuario o contraseña predeterminado en este proyecto. La cuenta `prueba` del entorno de demostración se creó separadamente, fuera de esta carpeta, y no se incluye en el despliegue.

Abra http://127.0.0.1:8766/admin. Cree un enlace con nombre, documento, celular, sucursal y despachador. Los enlaces locales solo funcionan desde ese equipo. El enlace vence en siete días; abrirlo no lo consume, finalizar sí. Su token se conserva como hash, y desaparece de la dirección visible al entrar. No comparta enlaces reales en sitios públicos.

## Publicación en VPS

1. Conserve este proyecto en un repositorio privado. No suba datos, claves ni `.env`.
2. Configure DNS del subdominio hacia la VPS. Instale Docker y Compose desde sus fuentes oficiales.
3. Copie el proyecto en `/opt/cargalibre`, copie `.env.example` como `.env` y complete DOMAIN y PUBLIC_URL con su dominio HTTPS.
4. Genere SECRET_KEY con `python3 -c 'import secrets; print(secrets.token_hex(32))'`. Guárdela únicamente en `.env`.
5. Revise las razones sociales, texto de autorización, URL real de política y derechos/canales de contacto. Ajuste POLICY en app.py si hace falta. Solo después marque `POLICY_APPROVED=yes`. La aplicación se niega a arrancar en producción sin esto y sin HTTPS.
6. `docker compose up -d --build`
7. `docker compose exec app flask --app 'app:create_app' create-admin`
8. Abra `https://su-dominio/admin` y haga una prueba ficticia completa antes de usar datos reales.

El volumen `records` contiene la base y la clave de firma. **Nunca use `docker compose down -v`**: elimina volúmenes. Al actualizar código use `docker compose up -d --build`; el volumen se conserva. Caddy obtiene y renueva HTTPS. No publique el puerto de la aplicación ni el de la base de datos: solo 80/443 y SSH restringido.

`TRUST_PROXY=yes` está diseñado para **un solo proxy Caddy**. El proxy sobrescribe X-Forwarded-For con la IP del cliente. Si añade Cloudflare u otro proxy deberá configurar explícitamente su cadena de confianza; no acepte IPs arbitrarias enviadas por el navegador. El entorno local registra 127.0.0.1. Mantenga NTP activo en la VPS.

## Copias y restauración

Las copias son locales: se guardan cifradas en `/data/backups` dentro del volumen `records`, en la misma VPS. **No protegen contra la pérdida de la VPS**: descárguelas periódicamente a otro equipo.

1. Genere una clave de respaldo Fernet:
   `docker compose exec app python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`
2. Guarde BACKUP_ENCRYPTION_KEY en `.env` **y en un gestor de contraseñas externo**. Perderla impide restaurar.
3. Recree los contenedores para cargar la variable: `docker compose up -d`.
4. `docker compose exec -T app python backup.py`

El script hace una instantánea consistente de SQLite (incluye PDFs y evidencias), verifica sellos e historial y cifra también la clave de firma.

Programe `/opt/cargalibre/backup-daily.sh` diariamente en la VPS (unidades systemd de ejemplo en `deploy/`). Cada copia nueva borra las de más de 14 días (`KEEP_DAYS` en backup.py). Para bajar las copias a su equipo:

```sh
docker compose cp app:/data/backups ./backups
```

Pruebe una restauración mensualmente en un directorio aislado y registre el resultado.

Exporte la clave pública del servidor y consérvela fuera de la VPS:

```sh
docker compose exec -T app python -c 'from app import create_app; print(create_app().config["PUBLIC_KEY"])' > public-key.txt
```

En un equipo de recuperación con dependencias instaladas, la variable BACKUP_ENCRYPTION_KEY disponible y la clave pública de confianza:

```sh
python backup.py --restore /ruta/copia.enc --data-dir ./recuperacion --public-key public-key.txt
python verify.py --database ./recuperacion/cargalibre.sqlite3 --public-key public-key.txt
```

El destino debe estar vacío. Se invalidan las sesiones de administrador restauradas. Antes de arrancar la aplicación recuperada configure una nueva SECRET_KEY, restablezca contraseñas si hubo una intrusión y revoque enlaces pendientes cuando corresponda. No se importa información sobre registros de un navegador; los expedientes siempre provienen de la base del servidor.

## Verificación independiente del comprobante

Desde el administrador descargue la evidencia JSON y el PDF. Verifique con la clave pública conservada **por separado**, no solo con la clave incluida en el JSON:

```sh
python verify.py --evidence expediente-evidencia.json --pdf expediente.pdf --public-key public-key.txt
```

## Operación y límites

- Filtros por placa, nombres o documento; resultados paginados de 50 en 50.
- No existen endpoints públicos de listado ni modificación del expediente.
- Contraseñas con scrypt, sesiones privadas con vencimiento de ocho horas, CSRF, límite de intentos y cookies seguras en producción.
- Los errores y logs no deben contener contraseñas ni tokens de enlaces. El despliegue no habilita logs de acceso con URLs privadas.
- No hay borrado automático de formularios. La conservación a largo plazo requiere presupuesto de almacenamiento, monitoreo, respaldos y una política de conservación conforme a la finalidad y obligaciones aplicables.
- La autorización del conductor no representa la aceptación del propietario o tenedor. El texto jurídico final requiere revisión de la organización.
- Se usa SQLite con WAL y transacciones atómicas, adecuado para esta carga inicial. No comparta la base por NFS ni ejecute múltiples VPS sobre el mismo archivo.

## Pruebas

```sh
python -m unittest discover -s tests -v
```

Se prueban guardado, rechazo de datos incompletos y teléfonos inválidos, CSRF, acceso privado, expiración y revocación, idempotencia del envío, filtros, inmutabilidad, detección de alteraciones, copia cifrada y restauración real. No se ha realizado despliegue en una VPS.

## Preguntas adicionales del formulario (versión 2)

Al final de los datos de quien diligencia se solicitan, sin respuesta preseleccionada y de forma obligatoria:

- ¿Usted es una Persona Expuesta Políticamente (PEP)? **Sí / No**.
- ¿Usted o la empresa que representa es familiar o tiene alguna relación con algún colaborador, cliente, proveedor o contraparte activa de CARGA LIBRE? **Sí / No**.

Las dos respuestas se validan también en el servidor, se conservan en mayúsculas en el expediente sellado y se muestran en el resumen previo a la firma, comprobante del administrador y PDF. No se modifica la estructura de la base de datos ni se alteran formularios ya firmados; los anteriores conservan su contenido original sin atribuirles respuestas que no dieron. Si un formulario estaba abierto durante la actualización, debe recargarse y revisarse antes de firmar.

Para actualizar una instalación existente, desde la carpeta de despliegue y conservando su `.env` y volumen de datos:

```sh
git pull --ff-only origin main
docker compose up -d --build
```

Estos comandos actualizan la aplicación; no ejecutan migraciones ni borran expedientes.
