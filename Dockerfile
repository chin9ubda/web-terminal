FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir aiohttp asyncssh

COPY server.py file_manager.py ./
COPY public/ public/

EXPOSE 8080

CMD ["python", "server.py"]
