import uvicorn
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/api/receive")
async def receive_data(request: Request):
    payload = await request.json()
    print(f"\n [LEGACY BUSINESS SERVER] Received plain data from proxy: {payload}")
    return {"status": "ACKNOWLEDGED", "message": "Data processed successfully by internal business logic."}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
