FROM tsl0922/ttyd:1.7.7 AS ttyd

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      wireguard-tools iproute2 iputils-ping openssh-client sshpass procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ttyd /usr/bin/ttyd /usr/bin/ttyd
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV PYTHONUNBUFFERED=1 DATA_DIR=/data WG_DIR=/etc/wireguard
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
