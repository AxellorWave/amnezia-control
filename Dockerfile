FROM python:3.12-slim
# только docker CLI (без демона) — чтобы управлять контейнерами VPN через docker.sock
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
CMD ["python", "-u", "-m", "app.main"]
