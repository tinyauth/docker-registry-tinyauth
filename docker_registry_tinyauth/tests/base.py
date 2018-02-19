import unittest
from unittest import mock

from docker_registry_tinyauth.app import create_app


class TestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.debug = True
        self.app.config['BUNDLE_ERRORS'] = True
        self.app.config['TESTING'] = True
        self.app.config['DEBUG'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app.config['TINYAUTH_BYPASS'] = True

        self.client = self.app.test_client()

        self._ctx = self.app.test_request_context()
        self._ctx.push()

    def tearDown(self):
        self._ctx.pop()

    def patch(self, *args, **kwargs):
        patcher = mock.patch(*args, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()
