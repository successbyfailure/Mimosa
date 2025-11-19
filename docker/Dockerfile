# Imagen base ligera para la API y dashboard
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mimosa mimosa

EXPOSE 8000
CMD ["uvicorn", "mimosa.web.main:app", "--host", "0.0.0.0", "--port", "8000"]
