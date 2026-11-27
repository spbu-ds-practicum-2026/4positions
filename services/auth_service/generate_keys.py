"""Create a local RSA pair without overwriting existing keys."""
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if __name__ == '__main__':
    directory = Path(__file__).resolve().parent / 'keys'
    directory.mkdir(mode=0o700, exist_ok=True)
    private, public = directory / 'private.pem', directory / 'public.pem'
    if private.exists() or public.exists():
        raise SystemExit('Keys already exist; refusing to overwrite')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with os.fdopen(os.open(private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as file:
        file.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with public.open('xb') as file:
        file.write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print('Created keys/private.pem and keys/public.pem; never share the private key.')
