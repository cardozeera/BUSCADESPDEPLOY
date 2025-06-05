#!/bin/bash

# Cria ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instala dependências com workaround pro erro da PEP 668
pip install --break-system-packages --upgrade pip
pip install --break-system-packages -r requirements.txt

# Roda o app
venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT
