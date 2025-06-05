from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.hash import bcrypt
from datetime import datetime
from supabase_config.supabase_client import supabase
from dotenv import load_dotenv
import os
import requests

load_dotenv()

app = FastAPI()

# ---- CORS ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- MODELOS ----

class Usuario(BaseModel):
    email: str
    senha: str

class ConsultaAuth(BaseModel):
    email: str
    senha: str
    tipo_busca: str
    termo: str
    resultado: str

# ---- ENDPOINTS SEM JWT ----

@app.get("/")
def root():
    return {"message": "🚀 API BuscaDesp sem JWT: use email+senha para /consulta."}

@app.get("/test-supabase")
def test_supabase():
    try:
        data = supabase.table("usuarios").select("*").limit(1).execute()
        return {"status": "success", "data": data.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/register")
def registrar_usuario(usuario: Usuario):
    # Hash da senha e grava no Supabase
    senha_criptografada = bcrypt.hash(usuario.senha)
    existe = supabase.table("usuarios").select("*").eq("email", usuario.email).execute()
    if existe.data:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    supabase.table("usuarios").insert({
        "email": usuario.email,
        "senha_hash": senha_criptografada,
        "criado_em": datetime.utcnow().isoformat()
    }).execute()
    return {"status": "ok", "usuario": usuario.email}

@app.post("/login")
def login_usuario(usuario: Usuario):
    # Valida email e senha e, se estiver tudo certo, retorna “Login válido”
    resultado = supabase.table("usuarios").select("*").eq("email", usuario.email).execute()
    if not resultado.data:
        raise HTTPException(status_code=401, detail="Email não encontrado")
    usuario_db = resultado.data[0]
    if not bcrypt.verify(usuario.senha, usuario_db["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    return {"status": "ok", "message": "Login válido"}

@app.post("/consulta")
def registrar_consulta(consulta: ConsultaAuth):
    # 1) Verifica se o usuário existe e a senha confere
    resultado = supabase.table("usuarios").select("*").eq("email", consulta.email).execute()
    if not resultado.data:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    usuario_db = resultado.data[0]
    if not bcrypt.verify(consulta.senha, usuario_db["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    usuario_id = usuario_db["id"]

    # 2) Grava a consulta no Supabase
    supabase.table("consultas").insert({
        "usuario_id": usuario_id,
        "tipo_busca": consulta.tipo_busca,
        "termo": consulta.termo,
        "resultado": consulta.resultado,
        "criado_em": datetime.utcnow().isoformat()
    }).execute()

    return {"status": "registrado", "usuario": consulta.email}

def enviar_resposta(numero: str, mensagem: str):
    instance_id = os.getenv("ZAPI_INSTANCE_ID")
    token = os.getenv("ZAPI_TOKEN")
    url = f"https://api.z-api.io/instances/{instance_id}/token/{token}/send-text"
    payload = {
        "phone": numero,
        "message": mensagem
    }
    try:
        response = requests.post(url, json=payload)
        print("✅ Resposta enviada:", response.text)
    except Exception as e:
        print("❌ Erro ao enviar resposta:", str(e))

@app.post("/webhook")
async def webhook(request: Request):
    try:
        payload = await request.json()
        print("📩 Mensagem recebida:", payload)
        mensagem = payload['messages'][0]['text']['body']
        numero = payload['messages'][0]['from']

        if mensagem.lower().startswith("login:"):
            resposta = f"✅ Login reconhecido!\nUsuário: {mensagem[6:].strip()}"
            enviar_resposta(numero, resposta)
        else:
            resposta = "🤖 Comando não reconhecido. Use 'login:seuemail'"
            enviar_resposta(numero, resposta)

        return {"status": "ok"}

    except Exception as e:
        print("❌ Erro ao processar webhook:", e)
        return {"status": "erro", "mensagem": str(e)}
