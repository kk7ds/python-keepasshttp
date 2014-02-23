import sys
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from StringIO import StringIO
import json
import base64
from Crypto.Cipher import AES
from Crypto import Random
from ConfigParser import ConfigParser
import uuid

import keepass_util

KEY = None
def new_iv():
    return Random.new().read(AES.block_size)

def aes_pad(data):
    pad_len = 16 - len(data) % 16
    pad_chr = chr(pad_len)
    return data + (pad_chr * pad_len)

def aes_unpad(data):
    pad_len = ord(data[-1])
    if pad_len <= 16:
        return data[:-pad_len]
    else:
        return data

class KeePassHTTPContext(object):
    def __init__(self, db_file, db_pass):
        self._db_util = keepass_util.KeePassUtil(db_file, db_pass)
        self._config = ConfigParser()
        self._config.read('pykeepasshttp.conf')
        if not self._config.has_section('general'):
            self._config.add_section('general')


    def _save_config(self):
        with file('pykeepasshttp.conf', 'w') as f:
            self._config.write(f)

    @property
    def key(self):
        return base64.b64decode(self._config.get('general', 'key'))

    @property
    def ident(self):
        if not self._config.has_option('general', 'ident'):
            self._config.set('general', 'ident', 'Default')
            self._save_config()
        return self._config.get('general', 'ident')

    def _verify(self, nonce64, verifier64, key64=None):
        if key64 is None:
            key = self.key
        else:
            key = base64.b64decode(key64)
        iv = base64.b64decode(nonce64)
        verifier = base64.b64decode(verifier64)
        aes = AES.new(key, AES.MODE_CBC, iv)
        cleartext = aes_unpad(aes.decrypt(verifier))
        return nonce64 == cleartext

    def _sign(self, resp):
        iv = new_iv()
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        nonce64 = base64.b64encode(iv)
        verifier64 = base64.b64encode(aes.encrypt(aes_pad(nonce64)))
        signature = {
            'Nonce': nonce64,
            'Verifier': verifier64,
            'Version': '2.0.0.0',
            'Hash': 'cd97d3fcda8935210741520aafc84630f0fefd25',
            'Id': self.ident,
        }
        resp.update(signature)

    def _decrypt(self, nonce64, data):
        aes = AES.new(self.key, AES.MODE_CBC, base64.b64decode(nonce64))
        return aes_unpad(aes.decrypt(data))

    def _encrypt(self, nonce64, data):
        aes = AES.new(self.key, AES.MODE_CBC, base64.b64decode(nonce64))
        return base64.b64encode(aes.encrypt(aes_pad(data)))

    def _test_associate(self, nonce64, verifier64, ident):
        if ident is None:
            return False
        if not self._config.has_option('general', 'key'):
            print "Rejecting unknown association: No Key Stored"
            return False
        if ident != self.ident:
            print 'Rejecting unknown association: Ident %s is wrong' % ident
            return False
        return self._verify(nonce64, verifier64)

    def test_associate(self, nonce64, verifier64, ident):
        resp = {'RequestType': 'test-associate',
                'Id': 'FIXME',
                }
        if self._test_associate(nonce64, verifier64, ident):
            resp['Success'] = True
            self._sign(resp)
        else:
            resp = {}
        return resp

    def associate(self, nonce64, verifier64, key64):
        resp = {
            'RequestType': 'associate',
            'Id': self.ident,
        }
        if not self._verify(nonce64, verifier64, key64):
            print "Failed verification for Associate"
            resp['Success'] = False
            return resp

        self._config.set('general', 'key', key64)
        self._save_config()
        print "Associated"

        resp['Success'] = True
        self._sign(resp)
        return resp

    def _make_entry(self, nonce64, entry):
        encentry = {}
        attrmap = {
            'Login': 'username',
            'Password': 'password',
            'Name': 'name',
            'Uuid': 'uuid',
        }

        for key, attr in attrmap.items():
            value = getattr(entry, attr)
            try:
                value = value()
            except TypeError:
                pass
            encentry[key] = self._encrypt(nonce64, value)

        return encentry

    def get_logins(self, nonce64, enc_url, enc_submit_url):
        url = self._decrypt(nonce64, base64.b64decode(enc_url))
        submit_url = self._decrypt(nonce64, base64.b64decode(enc_submit_url))
        entry = self._db_util.find_entry_by_url(submit_url)
        resp = {
            'RequestType': 'get-logins',
            }
        self._sign(resp)
        if not entry:
            resp['Success'] = False
        else:
            resp['Success'] = True
            resp['Entries'] = [self._make_entry(resp['Nonce'], entry)]
        return resp

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = json.loads(self.rfile.read(length))

        rt = data['RequestType']
        if rt == 'test-associate':
            resp = kpctxt.test_associate(data.get('Nonce'),
                                         data.get('Verifier'),
                                         data.get('Id'))
        elif rt == 'associate':
            resp = kpctxt.associate(data.get('Nonce'),
                                    data.get('Verifier'),
                                    data.get('Key'))
        elif rt == 'get-logins':
            resp = kpctxt.get_logins(data.get('Nonce'),
                                     data.get('Url'),
                                     data.get('SubmitUrl'))
        else:
            resp = {}


        s = StringIO()
        s.write(json.dumps(resp))
        self.send_response(resp and 200 or 404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(s.tell()))
        self.end_headers()
        s.seek(0)
        self.wfile.write(s.read())

if __name__ == '__main__':
    # Very hacky thing for testing
    kpctxt = KeePassHTTPContext('test.kdb', 'password')
    httpd = BaseHTTPServer.HTTPServer(('127.0.0.1', 19455), Handler)
    httpd.serve_forever()
