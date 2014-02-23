import StringIO
import json
import mock
import unittest

from keepasshttp import server


class HandlerWrapper(server.KeePassHTTPRequestHandler):
    def __init__(self):
        self.wfile = StringIO.StringIO()
        self.rfile = StringIO.StringIO()
        self.server = mock.MagicMock()

    def send_response(self, code):
        self._code = code

    def send_header(self, name, value):
        self.headers[name] = value

    def end_headers(self):
        pass


class TestKeePassSever(unittest.TestCase):
    def _req(self, handler, request):
        handler.rfile.write(json.dumps(request))
        headers = {'Content-Type': 'application/json',
                   'Content-Length': handler.rfile.tell()}
        handler.rfile.seek(0)
        handler.headers = headers
        handler.do_POST()
        actual_length = handler.wfile.tell()
        handler.wfile.seek(0)
        self.assertEqual('application/json', handler.headers['Content-Type'])
        length = int(handler.headers['Content-Length'])
        resp_data = handler.wfile.read(length)
        self.assertEqual(length, len(resp_data))
        self.assertEqual(length, actual_length)
        handler.wfile.read()
        self.assertEqual(length, handler.wfile.tell())
        return json.loads(resp_data)

    def test_test_associate(self):
        handler = HandlerWrapper()
        request = {'RequestType': 'test-associate',
                   'Nonce': 'nonce',
                   'Verifier': 'verifier',
                   'Id': 'id'}
        handler.server.context.test_associate.return_value = {
            'Success': True}
        resp = self._req(handler, request)
        handler.server.context.test_associate.assert_called_once_with(
            'nonce', 'verifier', 'id')
        self.assertEqual({'Success': True}, resp)
        self.assertEqual(handler._code, 200)

    def test_associate(self):
        handler = HandlerWrapper()
        request = {'RequestType': 'associate',
                   'Nonce': 'nonce',
                   'Verifier': 'verifier',
                   'Key': 'key'}
        handler.server.context.associate.return_value = {'Success': True}
        resp = self._req(handler, request)
        handler.server.context.associate.assert_called_once_with(
            'nonce', 'verifier', 'key')
        self.assertEqual({'Success': True}, resp)
        self.assertEqual(handler._code, 200)

    def test_get_logins(self):
        handler = HandlerWrapper()
        request = {'RequestType': 'get-logins',
                   'Nonce': 'nonce',
                   'Verifier': 'verifier',
                   'Url': 'url',
                   'SubmitUrl': 'suburl'}
        handler.server.context.get_logins.return_value = {'Success': True}
        resp = self._req(handler, request)
        handler.server.context.get_logins.assert_called_once_with(
            'nonce', 'verifier', 'url', 'suburl')
        self.assertEqual({'Success': True}, resp)
        self.assertEqual(handler._code, 200)

    def test_bad_request(self):
        handler = HandlerWrapper()
        request = {'RequestType': 'foo'}
        resp = self._req(handler, request)
        self.assertEqual({}, resp)
        self.assertEqual(handler._code, 404)

    def test_no_request(self):
        handler = HandlerWrapper()
        request = {'foo': 'bar'}
        resp = self._req(handler, request)
        self.assertEqual({}, resp)
        self.assertEqual(handler._code, 404)
