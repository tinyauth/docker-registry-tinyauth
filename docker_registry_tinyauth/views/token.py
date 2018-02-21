import datetime
from uuid import uuid4

import jwt
from flask import Blueprint, current_app, jsonify, request
from flask_tinyauth import api

from docker_registry_tinyauth.pki import (
    get_certificate,
    get_private_key,
    serialize_cert,
)
from docker_registry_tinyauth.scope import get_scopes

token_blueprint = Blueprint('auth', __name__)


@token_blueprint.route('/v2/token')
def get_token_for_request():
    try:
        service = request.args['service']
    except KeyError:
        response = jsonify({'error': 'service parameter required'})
        response.status_code = 400
        return response

    if service != current_app.config['TINYAUTH_SERVICE']:
        response = jsonify({'error': 'service parameter incorrect'})
        response.status_code = 400
        return response

    now = datetime.datetime.utcnow()

    permit = {}
    for scope in get_scopes():
        for action in scope['actions']:
            res = permit.setdefault(action, set())
            res.add(api.format_arn(scope['type'], scope['name']))
    for key in permit:
        permit[key] = list(permit[key])

    context = {
        'SourceIp': request.remote_addr,
        'RequestDateTime': now.isoformat(),
    }

    if not current_app.config['TINYAUTH_BYPASS']:
        response = api.call('authorize-by-token', {
            'permit': permit,
            'headers': request.headers.to_wsgi_list(),
            'context': context,
        })

        allowed = {}
        for action, resources in response['Permitted'].items():
            action = action.split(':', 1)[1]
            for resource in resources:
                resource = resource.rsplit(':', 1)[1]
                allowed.setdefault(resource, []).append(action)

        access = []
        for resource, actions in allowed.items():
            resource_type, resource = resource.split('/', 1)
            access.append({
                'type': resource_type,
                'name': resource,
                'actions': actions,
            })

        identity = response.get('Identity', '')

    else:
        access = []
        for scope in get_scopes():
            access.append({
                'type': scope['type'],
                'name': scope['name'],
                'actions': scope['actions'],
            })
        identity = 'root'

    expires = now + datetime.timedelta(seconds=current_app.config['EXPIRES_IN'])

    token_payload = {
        'iss': current_app.config['ISSUER'],
        'sub': identity,
        'aud': service,
        'exp': expires,
        'nbf': now,
        'iat': now,
        'jti': uuid4().hex,
        'access': access,
    }

    cert = get_certificate()

    response = {
        'token': jwt.encode(
            token_payload,
            get_private_key(),
            headers={
                'x5c': [serialize_cert(cert)],
            },
            algorithm='RS256',
        ).decode('utf-8'),
        'expires_in': current_app.config['EXPIRES_IN'],
        'issued_at': now.isoformat() + 'Z'
    }

    return jsonify(response)
