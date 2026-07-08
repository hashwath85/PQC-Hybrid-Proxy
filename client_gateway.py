import os
import uvicorn
import yaml
import requests
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from oqs import KeyEncapsulation
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()

app = FastAPI()

TARGET_SERVER_HOST = config["network"]["server_host"]
TARGET_SERVER_PORT = config["network"]["server_port"]
AUTH_TOKEN = config["security"]["auth_token"]

PROTOCOL = "https" if config["tls"]["enabled"] else "http"
SERVER_URL = f"{PROTOCOL}://{TARGET_SERVER_HOST}:{TARGET_SERVER_PORT}"
GATEWAY_HEADERS = {"X-Gateway-Auth-Token": AUTH_TOKEN}

class InboundPlaintextPayload(BaseModel):
    message: str

@app.post("/transmit")
def transmit_data(payload: InboundPlaintextPayload):
    try:
        handshake_response = requests.get(
            f"{SERVER_URL}/handshake", 
            headers=GATEWAY_HEADERS, 
            verify=False, 
            timeout=5
        )
        handshake_response.raise_for_status()
            
        handshake_data = handshake_response.json()
        session_id = handshake_data["session_id"]
        server_pq_public_bytes = bytes.fromhex(handshake_data["pq_public_key_hex"])
        server_ec_public_bytes = bytes.fromhex(handshake_data["ec_public_hex"])
        
        client_pq_kem = KeyEncapsulation("ML-KEM-1024")
        pq_ciphertext, pq_shared_secret = client_pq_kem.encap_secret(server_pq_public_bytes)
        
        client_ec_private = ec.generate_private_key(ec.SECP384R1())
        client_ec_public = client_ec_private.public_key()
        
        server_ec_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), server_ec_public_bytes)
        ec_shared_secret = client_ec_private.exchange(ec.ECDH(), server_ec_public)
        
        combined_secret = ec_shared_secret + pq_shared_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-gateway-symmetric-key",
        )
        hybrid_master_key = hkdf.derive(combined_secret)
        
        aesgcm = AESGCM(hybrid_master_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload.message.encode(), None)
        
        client_ec_public_bytes = client_ec_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        transmission_payload = {
            "session_id": session_id,
            "pq_ciphertext": pq_ciphertext.hex(),
            "client_ec_public_hex": client_ec_public_bytes.hex(),
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex()
        }
        
        send_response = requests.post(
            f"{SERVER_URL}/secure-receive", 
            json=transmission_payload, 
            headers=GATEWAY_HEADERS, 
            verify=False, 
            timeout=5
        )
        send_response.raise_for_status()
        return send_response.json()
        
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Gateway routing link offline: Cannot connect to target server at {SERVER_URL}. Verify target_server.py is running and TLS settings match."
        )
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Handshake network connection timed out. Check your firewall and network configuration."
        )
    except requests.exceptions.HTTPError as he:
        status_code = he.response.status_code if he.response is not None else 502
        error_detail = he.response.text if he.response is not None else str(he)
        raise HTTPException(
            status_code=status_code,
            detail=f"Target server rejected transaction with code {status_code}. Response: {error_detail}"
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Local Mathematical/Parsing Fault: Key representation mismatch. Details: {str(ve)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unhandled Gateway Internal Exception: {str(e)}"
        )

if __name__ == "__main__":
    uvicorn.run(
        app, 
        host=config["network"]["gateway_host"], 
        port=config["network"]["gateway_port"]
    )
