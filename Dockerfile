FROM node:20-slim AS ui-builder

WORKDIR /app/mimosa-ui

COPY mimosa-ui/package.json ./
RUN npm install --no-audit --no-fund
COPY mimosa-ui/ ./
RUN npm run build

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MIMOSA_ENV=production

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mimosa ./mimosa
COPY version.json ./version.json
COPY env.example .
COPY README.md .
COPY --from=ui-builder /app/mimosa-ui/build /app/mimosa/web/static/ui
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "mimosa.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
