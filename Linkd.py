import asyncio
import websockets
import subprocess
import random
import sys
import shutil
import re
import time
import aioconsole
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class EncryptionManager:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.aesgcm = None

    def derive_shared_key(self, peer_public_key_bytes):
        """Derive shared encryption key from peer's public key"""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        
        # Derive fixed-length symmetric key
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure_chat',
        )
        self.shared_key = kdf.derive(shared_secret)
        self.aesgcm = AESGCM(self.shared_key)

    def encrypt_message(self, message):
        """Encrypt message with new random nonce"""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, message.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_message(self, encrypted_data):
        """Decrypt message from base64-encoded data"""
        data = base64.b64decode(encrypted_data)
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None).decode()

async def chat_handler(websocket, peer_name, enc_manager):
    try:
        while True:
            encrypted_data = await websocket.recv()
            try:
                msg = enc_manager.decrypt_message(encrypted_data)
                print(f"\n{peer_name}: {msg}\n> ", end="", flush=True)
            except (InvalidTag, ValueError) as e:
                print(f"\n⚠️ Failed to decrypt message: {e}")
    except websockets.exceptions.ConnectionClosed:
        print("\n🔌 Peer disconnected.")

async def send_messages(websocket, my_name, enc_manager):
    try:
        while True:
            msg = await aioconsole.ainput("> ")
            if msg.lower() in ["exit", "quit"]:
                await websocket.close()
                break
            encrypted_msg = enc_manager.encrypt_message(msg)
            await websocket.send(encrypted_msg)
    except Exception as e:
        print(f"❌ Error sending message: {e}")

async def key_exchange(websocket, enc_manager):
    """Exchange public keys securely"""
    # Send our public key
    my_pubkey = enc_manager.public_key.public_bytes_raw()
    await websocket.send(base64.b64encode(my_pubkey).decode())
    
    # Receive peer's public key
    peer_pubkey_b64 = await websocket.recv()
    peer_pubkey = base64.b64decode(peer_pubkey_b64)
    enc_manager.derive_shared_key(peer_pubkey)

async def listen_on_websocket(port):
    async def handler(websocket):
        path = websocket.request.path
        if path != "/ws":
            print(f"❌ Rejected connection on invalid path: {path}")
            await websocket.close()
            return

        # Initialize encryption
        enc_manager = EncryptionManager()
        
        # Name exchange
        my_name = await aioconsole.ainput("Enter your name: ")
        await websocket.send(my_name)
        peer_name = await websocket.recv()
        
        # Perform key exchange
        await key_exchange(websocket, enc_manager)
        
        print(f"🔐 End-to-end encryption established with {peer_name}")
        print("💬 Start chatting (type 'exit' to quit)")

        await asyncio.gather(
            chat_handler(websocket, peer_name, enc_manager),
            send_messages(websocket, my_name, enc_manager)
        )

    server = await websockets.serve(handler, "0.0.0.0", port)
    actual_port = server.sockets[0].getsockname()[1]
    print(f"🟢 WebSocket server listening on port {actual_port}")

    proc, domain = start_cloudflare_tunnel_http(actual_port)
    if domain:
        print(f"🌐 Share this with your peer: wss://{domain}/ws")
        time.sleep(5)  # Wait for tunnel readiness
    else:
        print("❌ Tunnel setup failed.")
        sys.exit(1)

    await server.wait_closed()
    if proc:
        proc.terminate()

async def connect_to_websocket(uri):
    if not uri.startswith(("ws://", "wss://")):
        uri = "wss://" + uri
    if not uri.endswith("/ws"):
        uri = uri.rstrip("/") + "/ws"

    print(f"🔗 Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            # Initialize encryption
            enc_manager = EncryptionManager()
            
            # Name exchange
            my_name = await aioconsole.ainput("Enter your name: ")
            await websocket.send(my_name)
            peer_name = await websocket.recv()
            
            # Perform key exchange
            await key_exchange(websocket, enc_manager)
            
            print(f"🔐 End-to-end encryption established with {peer_name}")
            print("💬 Start chatting (type 'exit' to quit)")

            await asyncio.gather(
                chat_handler(websocket, peer_name, enc_manager),
                send_messages(websocket, my_name, enc_manager)
            )
    except Exception as e:
        print(f"❌ Connection failed: {e}")

def start_cloudflare_tunnel_http(local_port):
    if not shutil.which("cloudflared"):
        print("❌ 'cloudflared' not found. Please install it first.")
        return None, None

    cmd = ["cloudflared", "tunnel", "--url", f"http://localhost:{local_port}"]
    print("🌐 Starting Cloudflare Tunnel...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    domain = None
    start_time = time.time()
    while time.time() - start_time < 15:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        print(f"[cloudflared] {line.strip()}")
        match = re.search(r'https://([a-zA-Z0-9\-]+)\.trycloudflare\.com', line)
        if match:
            domain = match.group(1) + ".trycloudflare.com"
            break
    return proc, domain

def main():
    print("🔒 Secure Sayun P2P Chat (E2E Encrypted)")
    print("----------------------------------------")
    print("Choose a mode:")
    print("  [1] Listen (host chat room)")
    print("  [2] Connect to peer chat room")
    choice = input("Enter choice [1/2]: ").strip()

    if choice == '1':
        port = input("Enter port to listen on (blank = auto): ").strip()
        port = int(port) if port else random.randint(3000, 9000)
        print(f"📡 Starting secure listener on port {port}...")
        asyncio.run(listen_on_websocket(port))

    elif choice == '2':
        uri = input("Enter peer WebSocket address (wss://...): ").strip()
        asyncio.run(connect_to_websocket(uri))

    else:
        print("❌ Invalid choice.")

if __name__ == "__main__":
    main()

