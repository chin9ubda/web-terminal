FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash locales \
    && sed -i '/ko_KR.UTF-8/s/^# //' /etc/locale.gen \
    && locale-gen \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=ko_KR.UTF-8 LC_ALL=ko_KR.UTF-8

WORKDIR /app

RUN pip install --no-cache-dir aiohttp asyncssh

COPY server.py file_manager.py ./
COPY public/ public/

EXPOSE 8080

CMD ["python", "/app/server.py"]
