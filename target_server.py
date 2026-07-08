import os
import time
import asyncio
import uvicorn
import gc
import yaml
import requests
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Depends, status
from pydantic import BaseModel
from oqs import KeyEncapsulation
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import cryptography.exceptions

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()

server_sessions = {}

# Tracking structures to rate-limit endpoints independently
handshake_timestamps = {}
receive_timestamps = {}

SESSION_TTL = float(config["security"]["session_ttl"])
RATE_LIMIT_WINDOW = float(config["security"]["rate_limit_window"])
AUTH_TOKEN = config["security"]["auth_token"]
TARGET_DESTINATION_URL = config["forwarding"]["target_destination_url"]

async def verify_gateway_security(request: Request):
    client_ip = request.client.host
    now = time.time()
    path = request.url.path
    
    # Evaluate rate limits distinctly based on the request URI path
    if path == "/handshake":
        if client_ip in handshake_timestamps and (now - handshake_timestamps[client_ip] < RATE_LIMIT_WINDOW):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
                detail="Handshake rate limit exceeded."
            )
        handshake_timestamps[client_ip] = now
    elif path == "/secure-receive":
        if client_ip in receive_timestamps and (now - receive_timestamps[client_ip] < RATE_LIMIT_WINDOW):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
                detail="Transmission rate limit exceeded."
            )
        receive_timestamps[client_ip] = now

    api_key = request.headers.get("X-Gateway-Auth-Token")
    if api_key != AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Unauthorized gateway token."
        )

async def session_janitor():
    while True:
        await asyncio.sleep(5)
        now = time.time()
        stale_sessions = []
        
        for session_id, session_data in list(server_sessions.items()):
            if now - session_data["created_at"] > SESSION_TTL:
                stale_sessions.append(session_id)
                
        for session_id in stale_sessions:
            try:
                server_sessions[session_id]["pq_kem"].close()
            except Exception:
                pass
            del server_sessions[session_id]
            
        if stale_sessions:
            gc.collect()

@asynccontextmanager
async def lifespan(app: FastAPI):
    janitor_task = asyncio.create_task(session_janitor())
    yield
    janitor_task.cancel()

app = FastAPI(lifespan=lifespan)

class EncryptedPayload(BaseModel):
    session_id: str
    pq_ciphertext: str
    client_ec_public_hex: str
    nonce_hex: str
    ciphertext_hex: str

@app.get("/handshake", dependencies=[Depends(verify_gateway_security)])
def handshake():
    session_id = os.urandom(8).hex()
    
    receiver_pq_kem = KeyEncapsulation("ML-KEM-1024")
    pq_public_key = receiver_pq_kem.generate_keypair()
    
    server_ec_private = ec.generate_private_key(ec.SECP384R1())
    server_ec_public = server_ec_private.public_key()
    
    ec_public_hex = server_ec_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ).hex()
    
    server_sessions[session_id] = {
        "pq_kem": receiver_pq_kem,
        "ec_private": server_ec_private,
        "created_at": time.time()
    }
    
    return {
        "session_id": session_id,
        "pq_public_key_hex": pq_public_key.hex(),
        "ec_public_hex": ec_public_hex
    }

@app.post("/secure-receive", dependencies=[Depends(verify_gateway_security)])
def secure_receive(payload: EncryptedPayload):
    session = server_sessions.get(payload.session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired session state.")
        
    try:
        pq_kem = session["pq_kem"]
        pq_ciphertext = bytes.fromhex(payload.pq_ciphertext)
        pq_shared_secret = pq_kem.decap_secret(pq_ciphertext)
        
        client_public_bytes = bytes.fromhex(payload.client_ec_public_hex)
        client_ec_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_public_bytes)
        ec_shared_secret = session["ec_private"].exchange(ec.ECDH(), client_ec_public)
        
        combined_secret = ec_shared_secret + pq_shared_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-gateway-symmetric-key",
        )
        hybrid_master_key = hkdf.derive(combined_secret)
        
        del server_sessions[payload.session_id]
        
        try:
            mutable_secret = bytearray(combined_secret)
            for i in range(len(mutable_secret)): mutable_secret[i] = 0
        except Exception:
            pass

        aesgcm = AESGCM(hybrid_master_key)
        nonce = bytes.fromhex(payload.nonce_hex)
        ciphertext = bytes.fromhex(payload.ciphertext_hex)
        
        decrypted_plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
        
        try:
            forward_response = requests.post(
                TARGET_DESTINATION_URL, 
                json={"data": decrypted_plaintext}, 
                timeout=5
            )
            return {
                "status": "SUCCESS", 
                "forward_status_code": forward_response.status_code,
                "forward_response": forward_response.text
            }
        except requests.exceptions.RequestException as re:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, 
                detail=f"Downstream Forwarding Failure: Decryption succeeded, but the legacy business server at {TARGET_DESTINATION_URL} could not be reached. Details: {str(re)}"
            )
        
    except cryptography.exceptions.InvalidTag:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Security Violation: Ciphertext authentication tag verification failed (data was modified or key is incorrect)."
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Data Parsing Error: Hexadecimal decoding or key formatting failed. Details: {str(ve)}"
        )
    except TypeError as te:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, 
            detail=f"Type Initialization Error: Cryptographic engine received invalid parameters. Details: {str(te)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Unexpected Cryptographic Runtime Fault: {str(e)}"
        )
    finally:
        if payload.session_id in server_sessions:
            del server_sessions[payload.session_id]
        gc.collect()

if __name__ == "__main__":
    host = config["network"]["server_host"]
    port = config["network"]["server_port"]
    
    if config["tls"]["enabled"]:
        uvicorn.run(
            app, 
            host=host, 
            port=port, 
            ssl_keyfile=config["tls"]["key_file"], 
            ssl_certfile=config["tls"]["cert_file"]
        )
    else:
        uvicorn.run(app, host=host, port=port)
