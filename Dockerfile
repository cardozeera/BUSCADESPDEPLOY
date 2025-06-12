# 1) Base: Python leve
FROM python:3.11-slim

# 2) Diretório de trabalho dentro do container
WORKDIR /app

# 3) Copia só o requirements e instala libs
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4) Copia todo o seu código
COPY . .

# 5) Expõe a porta que seu FastAPI vai usar
EXPOSE 8000

# 6) Comando padrão pra rodar seu app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--timeout-keep-alive", "120"]
