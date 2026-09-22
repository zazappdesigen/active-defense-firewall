FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
USER root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["python", "-m", "active_defense_firewall"]
