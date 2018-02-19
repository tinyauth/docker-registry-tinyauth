from flask import Flask

from docker_registry_tinyauth.pki import get_certificate
from docker_registry_tinyauth.views import token_blueprint


def create_app():
    app = Flask(__name__)

    app.config['EXPIRES_IN'] = 3600
    app.config['ISSUER'] = 'tinyauth'

    app.config['TINYAUTH_SERVICE'] = 'docker-registry'
    app.config['TINYAUTH_REGION'] = 'eu-west-1'
    app.config['TINYAUTH_PARTITION'] = 'primary'
    app.config['TINYAUTH_ENDPOINT'] = 'http://tinyauth:5000/'
    app.config['TINYAUTH_ACCESS_KEY_ID'] = 'gatekeeper'
    app.config['TINYAUTH_SECRET_ACCESS_KEY'] = 'keymaster'

    app.register_blueprint(token_blueprint)

    with app.app_context():
        get_certificate()

    return app


app = create_app()
