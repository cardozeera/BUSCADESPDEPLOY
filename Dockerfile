FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Expõe explicitamente a porta (muito importante)
EXPOSE 8000

# Start do app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
