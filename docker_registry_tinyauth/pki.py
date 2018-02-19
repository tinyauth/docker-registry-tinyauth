import datetime
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from flask import current_app


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def load_private_key(private_key):
    return serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend(),
    )


def save_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def get_private_key():
    if os.path.exists('/certificates/server.key'):
        with open('/certificates/server.key', 'rb') as fp:
            return load_private_key(fp.read())

    private_key = generate_private_key()

    with open('/certificates/server.key', 'wb') as fp:
        fp.write(save_private_key(private_key))

    return private_key


def generate_certificate():
    private_key = get_private_key()
    public_key = private_key.public_key()

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, current_app.config['TINYAUTH_SERVICE'])
    ])

    now = datetime.datetime.utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=100*365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=True)
    )

    return builder.sign(private_key, hashes.SHA256(), default_backend())


def load_certificate(cert):
    return load_pem_x509_certificate(
        cert,
        default_backend()
    )


def save_certificate(cert):
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def get_certificate():
    if os.path.exists('/certificates/server.pem'):
        with open('/certificates/server.pem', 'rb') as fp:
            return load_certificate(fp.read())

    cert = generate_certificate()

    with open('/certificates/server.pem', 'wb') as fp:
        fp.write(save_certificate(cert))

    return cert


def serialize_cert(cert):
    return ''.join(
        cert.public_bytes(serialization.Encoding.PEM).
        decode('utf-8').
        strip().
        split('\n')[1:-1]
    )
