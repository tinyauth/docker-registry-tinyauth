from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate


def get_certificate():
    with open('/certificates/server.pem', 'rb') as fp:
        return load_pem_x509_certificate(
            fp.read(),
            default_backend()
        )


def serialize_cert(cert):
    return ''.join(
        cert.public_bytes(serialization.Encoding.PEM).
        decode('utf-8').
        strip().
        split('\n')[1:-1]
    )


def get_private_key():
    with open('/certificates/server.key', 'rb') as fp:
        private_key = serialization.load_pem_private_key(
            fp.read(),
            password=None,
            backend=default_backend()
        )
        return private_key
