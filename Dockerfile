FROM python:3.12-slim
# только docker CLI (без демона) — чтобы делать docker exec в контейнер Амнезии
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bot.py .
CMD ["python", "-u", "bot.py"]
