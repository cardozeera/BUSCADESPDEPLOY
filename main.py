from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.hash import bcrypt
from datetime import datetime, timedelta
from jose import JWTError, jwt
from supabase_config.supabase_client import supabase
from dotenv import load_dotenv
import os
import requests

load_dotenv()

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def criar_token(dados: dict, expira_em: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = dados.copy()
    expire = datetime.utcnow() + expira_em
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def validar_token(authorization: str = Header(...)):
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("email")
    except (JWTError, IndexError):
        raise HTTPException(status_code=401, detail="Token inválido ou ausente")

# Models
class Usuario(BaseModel):
    email: str
    senha: str

class Consulta(BaseModel):
    tipo_busca: str
    termo: str
    resultado: str

@app.get("/")
def root():
    return {"message": "🚀 API BuscaDesp com JWT ativa."}

@app.get("/test-supabase")
def test_supabase():
    try:
        data = supabase.table("usuarios").select("*").limit(1).execute()
        return {"status": "success", "data": data.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/register")
def registrar_usuario(usuario: Usuario):
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
    resultado = supabase.table("usuarios").select("*").eq("email", usuario.email).execute()
    if not resultado.data:
        raise HTTPException(status_code=401, detail="Email não encontrado")
    usuario_db = resultado.data[0]
    if not bcrypt.verify(usuario.senha, usuario_db["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    token = criar_token({"email": usuario.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/consulta")
def registrar_consulta(consulta: Consulta, email: str = Depends(validar_token)):
    usuario = supabase.table("usuarios").select("id").eq("email", email).execute()
    if not usuario.data:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    usuario_id = usuario.data[0]["id"]
    supabase.table("consultas").insert({
        "usuario_id": usuario_id,
        "tipo_busca": consulta.tipo_busca,
        "termo": consulta.termo,
        "resultado": consulta.resultado,
        "criado_em": datetime.utcnow().isoformat()
    }).execute()
    return {"status": "registrado", "usuario": email}

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
