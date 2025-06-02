from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "BuscaDesp Backend Rodando com FastAPI"}
