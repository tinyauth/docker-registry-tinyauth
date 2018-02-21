import os

from flask import Flask

from docker_registry_tinyauth.pki import get_certificate
from docker_registry_tinyauth.views import token_blueprint


def create_app():
    app = Flask(__name__)

    app.config['EXPIRES_IN'] = 3600
    app.config['ISSUER'] = 'tinyauth'

    app.config['TINYAUTH_SERVICE'] = os.environ.get('TINYAUTH_SERVICE', 'docker-registry')
    app.config['TINYAUTH_PARTITION'] = os.environ.get('TINYAUTH_PARTITION', '')
    app.config['TINYAUTH_REGION'] = os.environ.get('TINYAUTH_REGION', '')
    app.config['TINYAUTH_ENDPOINT'] = os.environ.get('TINYAUTH_ENDPOINT', '')
    app.config['TINYAUTH_ACCESS_KEY_ID'] = os.environ.get('TINYAUTH_ACCESS_KEY_ID', '')
    app.config['TINYAUTH_SECRET_ACCESS_KEY'] = os.environ.get('TINYAUTH_SECRET_ACCESS_KEY', '')
    app.config['TINYAUTH_BYPASS'] = 'TINYAUTH_BYPASS' in os.environ

    app.register_blueprint(token_blueprint)

    with app.app_context():
        get_certificate()

    return app


app = create_app()
