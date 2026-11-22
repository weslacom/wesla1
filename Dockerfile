
FROM python:3.12-slim
WORKDIR /app
COPY wesla-supabase-connected.zip /tmp/wesla.zip
RUN apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip -q /tmp/wesla.zip -d /tmp/wesla-src \
    && cp -a /tmp/wesla-src/wesla-real/. /app/ \
    && rm -rf /tmp/wesla-src /tmp/wesla.zip /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt
ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
