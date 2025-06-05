#!/bin/bash

# Cria e ativa ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instala dependências no ambiente virtual
pip install --upgrade pip
pip install -r requirements.txt

# Roda a aplicação usando uvicorn do ambiente virtual
venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT
