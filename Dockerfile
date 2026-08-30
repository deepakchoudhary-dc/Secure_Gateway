# AI Security Gateway — application container
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 gateway \
    && mkdir /app/logs \
    && chown -R gateway:gateway /app

COPY src ./src
COPY alembic.ini run.py ./
COPY migrations ./migrations

USER gateway
EXPOSE 8000
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
