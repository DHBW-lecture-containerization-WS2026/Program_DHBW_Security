from fastapi import FastAPI

app = FastAPI(title="Security Hub")


@app.get("/")
def home():
    return {"message": "Security Hub is running!"}


@app.get("/health")
def health():
    return {"status": "ok"}