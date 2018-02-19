import datetime
import json

from . import base


class TestIssueToken(base.TestCase):

    def setUp(self):
        super().setUp()
        self.call = self.patch('flask_tinyauth.api.call')

        frozen_time = datetime.datetime(2018, 1, 3, 16, 50, 0)
        dt = self.patch('docker_registry_tinyauth.views.token.datetime.datetime')
        dt.utcnow.return_value = frozen_time

    def test_simple_issue(self):
        self.call.return_value = {
            'Identity': 'root',
            'Permitted': {
                'test:push': [
                    ':repository/sambalba/my-app',
                ]
            },
        }

        response = self.client.get('/token?service=docker-registry&client_id=client&scope=repository:samalba/my-app:push')

        assert response.status_code == 200

        payload = json.loads(response.get_data(as_text=True))
        assert 'token' in payload

        self.call.assert_called_with('authorize-by-token', {
            'permit': {
                'docker-registry:push': [
                    'arn:primary:docker-registry:eu-west-1::repository/samalba/my-app'
                ]
            },
            'headers': [
                ('User-Agent', 'werkzeug/0.14.1'),
                ('Host', 'localhost'),
                ('Content-Length', '0')
            ],
            'context': {
                'SourceIp': '127.0.0.1',
                'RequestDateTime': '2018-01-03T16:50:00'
            }
        })
