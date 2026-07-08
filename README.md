<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">

<h1 style="text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; margin-top: 40px;">
    Hybrid Post-Quantum Cryptography (PQC) Reverse Proxy<br>
    <span style="font-size: 16px; color: #666; font-weight: normal;">Production-Grade Enterprise Network Security Core</span>
</h1>

<p style="text-align: center; font-style: italic; color: #555; margin-bottom: 50px;">
    Technical Architecture, Implementation Framework, and Deployment Blueprint
</p>

## 1. Executive & Architectural Overview

The **Hybrid Post-Quantum Cryptography (PQC) Reverse Proxy** is a high-performance, modular network security framework designed to protect legacy applications from quantum computing interception models, specifically the **"Harvest Now, Decrypt Later"** paradigm. Under this threat model, adversarial entities capture encrypted enterprise transit traffic today with the intention of decapsulating it once cryptanalytically viable quantum computers become available.

To mitigate this risk without sacrificing backwards-compatible security parameters, this system enforces a **dual-layered hybrid key encapsulation mechanism (KEM)**. By combining next-generation lattice-based cryptography with established elliptic-curve protocols, the system guarantees that data remains secure even if one of the underlying mathematical algorithms is completely compromised in the future.

### Cryptographic Foundation
* **Post-Quantum Layer:** `ML-KEM-1024` (Module-Lattice Key Encapsulation Mechanism), fully compliant with the **FIPS 203** standardization framework. This provides a maximum quantum security margin equivalent to AES-256 bit strength.
* **Classical Layer:** `ECDH` using the `SECP384R1` (NIST P-384) elliptic curve, providing established, high-performance classical asymmetric defense.
* **Symmetric Encryption:** `AES-256-GCM` (Galois/Counter Mode). This authenticated encryption with associated data (AEAD) algorithm ensures complete confidentiality and cryptographic data integrity validation across the network boundary.

---

<div style="page-break-before: always;"></div>

## 2. Technical Component Pipeline

The infrastructure maps out distinct operational proxies to decouple cryptographic overhead from legacy business application workflows.

### 2.1 Client Gateway Proxy (`client_gateway.py`)
Operating directly inside the local application perimeter, this asset acts as an interceptor loop. It receives raw plaintext data over internal loopback ports, contacts the target server to initiate an ephemeral hybrid handshake, derives a symmetric key matrix, wraps the message in an authenticated cryptographic capsule, and handles secure network egress.

### 2.2 Target Security Server (`target_server.py`)
Positioned at the edge of the secure destination infrastructure, this component serves as the hardened gateway entry point. It hosts the handshake endpoint, enforces network rate limiting, processes post-quantum decapsulation routines to derive identical master keys, decrypts the inbound stream, and immediately proxies clean plaintext data to internal application destinations.

---

## 3. Global Matrix Configuration (`config.yaml`)

System variables, interface routing ports, and authentication tokens are externalized inside a central configuration file to facilitate automated environment orchestration and plug-and-play modularity.

```yaml
network:
  server_host: "127.0.0.1"    # Network interface binding for the target server
  server_port: 8002           # Port handling secure cryptographic incoming traffic
  gateway_host: "127.0.0.1"   # Interface binding for the local client proxy
  gateway_port: 8001          # Port catching raw application traffic locally

security:
  auth_token: "YOUR_SECURE_MESH_PASSPHRASE"  # Pre-shared validation key for mesh identity
  session_ttl: 30.0                          # Time-to-live in seconds before session states expire
  rate_limit_window: 1.0                     # Sliding window threshold for anti-burst defenses

tls:
  enabled: true                              # Enforces TLS encapsulation over transit lanes
  cert_file: "cert.pem"                      # Relative path to public certificate file
  key_file: "key.pem"                        # Relative path to private key file

forwarding:
  target_destination_url: "[http://127.0.0.1:8080/api/receive](http://127.0.0.1:8080/api/receive)"  # Internal legacy backend routing endpoint
```
<div style="page-break-before: always;"></div>

4. Operational Staging & Verification
Follow these sequential instructions to establish, verify, and run the hybrid proxy infrastructure locally.

4.1 System Prerequisites
Ensure the target environment contains Python 3.10+ along with liboqs and its respective Python bindings successfully linked to the runtime class paths. Install application layer packages via pip:

Bash
pip install fastapi uvicorn requests pyyaml cryptography
4.2 Generate Cryptographic Identity Material
Before booting proxies with TLS enabled, generate self-signed operational certificate authority arrays within the project folder root:

Bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
4.3 Component Boot Sequence
Launch the individual infrastructure scripts within isolated terminal windows or container definitions in the following order:

Boot the Legacy Destination Application:

Bash
python3 mock_business_server.py
Boot the Decryption Target Server Proxy:

Bash
python3 target_server.py
Boot the Local Client Encryption Gateway:

Bash
python3 client_gateway.py
4.4 Execute Data Transmission Test
Inject a sample plaintext payload directly into the client proxy ingest loop to verify data translation and end-to-end cryptographic integrity:

Bash
curl -X POST [http://127.0.0.1:8001/transmit](http://127.0.0.1:8001/transmit) \
     -H "Content-Type: application/json" \
     -d '{"message": "Confidential Production Data Assets"}'
<div style="page-break-before: always;"></div>

5. Security Architecture & Threat Mitigation
To maintain strict compliance with cybersecurity defensive design principles, the following hardening routines are natively compiled into the system core:

Isolated Path Rate-Limiting: To prevent algorithmic denial-of-service or side-channel brute-forcing attacks, rate-limiting windows are split by path (/handshake and /secure-receive). This allows rapid multi-step handshakes from legitimate clients while throttling high-frequency brute-force parameter flooding.

Automated Session Janitor Context: An active asynchronous loop scans active handshake sessions in memory. States that do not close transactions within the session_ttl boundary are dropped, and their reference handles are closed.

Volatile Memory Scrubbing: Immediately following key derivation via the HKDF loop, secret material array references are targeted for immediate memory release, followed by active gc.collect() execution to prevent information exposure via memory dump exploitation vectors.

6. Licensing & Open Source Compliance
This core engine is published under the Apache License 2.0. Permissions include commercial use, modification, distribution, and private use, providing an ideal open-core foundation for building advanced, proprietary closed-source integration software modules.

</div>
