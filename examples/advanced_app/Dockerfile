ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim

RUN apt-get update && apt-get install -y \
    libsodium23 \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PIP_NO_CACHE_DIR=false \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=10 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY examples/advanced_app/requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

COPY examples/advanced_app/main.py /app/

RUN mkdir -p /app/data/ipinfo

EXPOSE 8000

CMD ["python", "main.py"]
