# ---- Base image ----
FROM python:3.10-slim

# ---- Environment ----
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# ---- System dependencies ----
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    libssl-dev \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# ---- Install cloudflared ----
RUN curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared \
    && chmod +x /usr/local/bin/cloudflared

# ---- Set working directory ----
WORKDIR /app

# ---- Copy project ----
COPY . /app

# ---- Upgrade pip ----
RUN pip install --upgrade pip

# ---- Python dependencies ----
# Use released wheels (fast, stable, no Rust builds)
RUN pip install \
    websockets \
    aioconsole \
    cryptography

# ---- Expose nothing explicitly (Cloudflare tunnel handles it) ----
# EXPOSE is optional and not required for cloudflared

# ---- Run Linkd ----
CMD ["python", "Linkd.py"]

