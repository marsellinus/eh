FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io bash \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && pip install --no-cache-dir pandas scikit-learn paramiko requests psutil

COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static

ENV PORT=5050
ENV DASHBOARD_ROOT=/workspace

EXPOSE 5050

CMD ["python", "/app/app.py"]
