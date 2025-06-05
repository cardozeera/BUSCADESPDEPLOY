# main.py
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

# ---- CORS ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- CONSTANTES JWT ----
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ---- MODELOS ----
class Usuario(BaseModel):
    email: str
    senha: str

class Consulta(BaseModel):
    tipo_busca: str
    termo: str
    resultado: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ---- FUNÇÕES AUXILIARES JWT ----
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

async def get_current_user(authorization: str = Header(...)):
    """
    Espera header: Authorization: Bearer <token>
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header Authorization inválido")
    token = authorization.split("Bearer ")[1]
    user_id = verify_token(token)
    return user_id

# ---- ENDPOINTS ----

@app.get("/")
def root():
    return {"message": "🚀 API BuscaDesp: use /login para obter token e depois /consulta com Authorization."}

@app.get("/test-supabase")
def test_supabase():
    try:
        data = supabase.table("usuarios").select("*").limit(1).execute()
        return {"status": "success", "data": data.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/login", response_model=TokenResponse)
def login_usuario(usuario: Usuario):
    # 1) Busca usuário no Supabase
    resultado = supabase.table("usuarios").select("*").eq("email", usuario.email).execute()
    if not resultado.data:
        raise HTTPException(status_code=401, detail="Email não encontrado")
    usuario_db = resultado.data[0]
    # 2) Verifica senha
    if not bcrypt.verify(usuario.senha, usuario_db["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    # 3) Gera JWT com sub = id do usuário
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token({"sub": str(usuario_db["id"])}, expires_delta=access_token_expires)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/consulta")
def registrar_consulta(
    consulta: Consulta,
    current_user_id: str = Depends(get_current_user)
):
    # 1) current_user_id já é validado pelo JWT
    # 2) Grava a consulta no Supabase
    supabase.table("consultas").insert({
        "usuario_id": current_user_id,
        "tipo_busca": consulta.tipo_busca,
        "termo": consulta.termo,
        "resultado": consulta.resultado,
        "criado_em": datetime.utcnow().isoformat()
    }).execute()
    return {"status": "registrado", "usuario_id": current_user_id}

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
