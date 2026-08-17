FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py main.py ./
COPY core/ core/
COPY services/ services/
COPY intel/ intel/

VOLUME ["/app/data", "/app/output"]

ENTRYPOINT ["python", "-u", "main.py"]
CMD ["--help"]
