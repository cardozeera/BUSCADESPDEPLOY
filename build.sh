#!/bin/bash

# Cria o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# Força o pip a instalar mesmo com restrição do sistema
pip install --upgrade pip
pip install --break-system-packages -r requirements.txt

# Inicia o FastAPI com uvicorn do ambiente virtual
.venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT
