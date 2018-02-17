from datetime import datetime, timedelta
import json
import re
from uuid import uuid4

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, Flask, current_app, jsonify, request
import jwt


SCOPE_RE = re.compile(r'^(?P<type>repository):(?P<name>[^:]+)(?::(?P<tag>[^:]))?:(?P<actions>.*)$')

auth_blueprint = Blueprint('auth', __name__)


def parse_scope(scope):
    parsed = SCOPE_RE.match(scope.strip().lower())
    return {
        'type': parsed.group('type'),
        'name': parsed.group('name'),
        'tag': parsed.group('tag'),
        'actions': parsed.group('actions').split(','),
    }


def get_scopes():
    scopes = list()
    for s in request.args.getlist('scope'):
        scopes.append(parse_scope(s))
    return scopes


def get_certificate():
    with open('/certificates/server.pem', 'rb') as fp:
        return load_pem_x509_certificate(
            fp.read(),
            default_backend()
        )


def serialize_cert(cert):
    return ''.join(
        cert.public_bytes(serialization.Encoding.PEM).\
            decode('utf-8').\
            strip().\
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


@auth_blueprint.route('/token')
def get_token_for_request():
    try:
        service = request.args['service']
    except KeyError:
        response = jsonify({'error': 'service parameter required'})
        response.status_code = 400
        return response

    if service != current_app.config['SERVICE']:
        response = jsonify({'error': 'service parameter incorrect'})
        response.status_code = 400
        return response

    scopes = get_scopes()

    # FIXME: Do access test here

    now = datetime.utcnow()
    expires = now + timedelta(seconds=current_app.config['EXPIRES_IN'])

    access = []
    for scope in scopes:
        access.append({
            'type': scope['type'],
            'name': scope['name'],
            'actions': scope['actions'],
        })

    token_payload = {
        'iss' : app.config['ISSUER'],
        'sub' : '',
        'aud' : service,
        'exp' : expires,
        'nbf' : now,
        'iat' : now,
        'jti' : uuid4().hex,
        'access' : access,
    }

    cert = get_certificate()

    response = {
        'token' : jwt.encode(
            token_payload,
            get_private_key(),
            headers = {
                'x5c': [serialize_cert(cert)],
            },
            algorithm='RS256',
        ).decode('utf-8'),
        'expires_in' : app.config['EXPIRES_IN'],
        'issued_at' : now.isoformat() + 'Z'
    }

    return jsonify(response)


def create_app():
    app = Flask(__name__)

    app.config['EXPIRES_IN'] = 3600
    app.config['SERVICE'] = 'docker-registry'
    app.config['ISSUER'] = 'tinyauth'

    app.register_blueprint(auth_blueprint)

    return app


app = create_app()
