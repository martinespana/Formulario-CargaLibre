FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home cargalibre && mkdir /data && chown cargalibre /data
COPY --chown=cargalibre:cargalibre . .
USER cargalibre
EXPOSE 8000
CMD ["gunicorn","--bind","0.0.0.0:8000","--workers","2","--threads","2","--timeout","60","--error-logfile","-","app:create_app()"]
