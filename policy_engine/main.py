from fastapi import FastAPI

app = FastAPI(title="NAC Policy Engine")

@app.get("/")
def read_root():
    return {"status": "healthy", "service": "policy_engine"}
