FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY mimosanpm_agent ./mimosanpm_agent

CMD ["python", "-m", "mimosanpm_agent.main"]
