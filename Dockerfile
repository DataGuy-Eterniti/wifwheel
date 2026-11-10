FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements-app.txt .
RUN pip install --no-cache-dir -r requirements-app.txt
COPY app.py scanner.py ./
COPY static ./static
RUN mkdir -p data/cache
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
