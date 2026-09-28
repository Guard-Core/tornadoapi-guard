ARG PYTHON_VERSION=3.10
FROM python:${PYTHON_VERSION}-slim

RUN apt-get update && apt-get install -y \
    libsodium23 \
    wget \
    build-essential \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PIP_NO_CACHE_DIR=false \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=10 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt /app/
COPY tornadoapi_guard-1.2.0-py3-none-any.whl /app/

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN mkdir -p /app/data/ipinfo

EXPOSE 8000

CMD ["python", "main.py"]
