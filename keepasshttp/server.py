# Copyright 2014 Dan Smith <dsmith@danplanet.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import BaseHTTPServer
import ConfigParser
from Crypto import Cipher
from Crypto import Random
from StringIO import StringIO
import base64
import json
import os

from keepasshttp import util

LOG = util.get_logger(__name__)


def new_iv():
    return Random.new().read(Cipher.AES.block_size)


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


def configfile_location():
    return os.path.join(os.getenv('HOME', '.'),
                        '.keepasshttp')


class KeePassHTTPContext(object):
    def __init__(self, db_file, db_pass, allow_associate=False,
                 timeout=None, config=None):
        self._db_file = db_file
        self._db_pass = db_pass
        self._db_util = util.KeePassUtil(db_file)
        if not callable(db_pass):
            self._db_util.unlock(db_pass)
        self._timeout = timeout is not None and timeout * 60 or 0
        if config:
            self._config = config
        else:
            self._config = ConfigParser.ConfigParser()
            self._config.read(configfile_location())
        self._allow_associate = allow_associate
        if not self._config.has_section('general'):
            self._config.add_section('general')

    def _save_config(self):
        with file(configfile_location(), 'w') as f:
            os.chmod(configfile_location(), 0600)
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
        aes = Cipher.AES.new(key, Cipher.AES.MODE_CBC, iv)
        cleartext = aes_unpad(aes.decrypt(verifier))
        return nonce64 == cleartext

    def _sign(self, resp):
        iv = new_iv()
        aes = Cipher.AES.new(self.key, Cipher.AES.MODE_CBC, iv)
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
        aes = Cipher.AES.new(self.key, Cipher.AES.MODE_CBC,
                             base64.b64decode(nonce64))
        return aes_unpad(aes.decrypt(data))

    def _encrypt(self, nonce64, data):
        aes = Cipher.AES.new(self.key, Cipher.AES.MODE_CBC,
                             base64.b64decode(nonce64))
        return base64.b64encode(aes.encrypt(aes_pad(data)))

    def _test_associate(self, nonce64, verifier64, ident):
        if ident is None:
            return False
        if not self._config.has_option('general', 'key'):
            LOG.warn('Rejecting unknown association: No Key Stored')
            return False
        if ident != self.ident:
            LOG.warn('Rejecting unknown association: Ident %s is wrong' %
                     ident)
            return False
        return self._verify(nonce64, verifier64)

    def test_associate(self, nonce64, verifier64, ident):
        resp = {'RequestType': 'test-associate',
                'Id': self.ident,
                }
        if self._test_associate(nonce64, verifier64, ident):
            LOG.debug('Confirming existing association')
            resp['Success'] = True
            self._sign(resp)
        else:
            LOG.debug('No existing association')
            resp = {}
        return resp

    def associate(self, nonce64, verifier64, key64):
        resp = {
            'RequestType': 'associate',
            'Id': self.ident,
        }
        if not self._allow_associate:
            LOG.warn('Refused to Associate (disabled)')
            resp['Success'] = False
            resp['Error'] = 'Association is disabled'
            return resp
        if not self._verify(nonce64, verifier64, key64):
            LOG.warn('Failed verification for Associate')
            resp['Success'] = False
            resp['Error'] = 'Key verification failed'
            return resp

        self._config.set('general', 'key', key64)
        self._save_config()
        LOG.info('Associated')

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

    def _get_login(self, url):
        if not url:
            return None

        try:
            return self._db_util.find_entry_by_url(url)
        except util.DatabaseLockedError:
            pass

        while True:
            db_pass = self._db_pass()
            if not db_pass:
                return None
            try:
                self._db_util.unlock(db_pass, timeout=self._timeout)
                return self._db_util.find_entry_by_url(url)
            except util.DatabaseLockedError:
                pass

    def get_logins(self, nonce64, verifier64, enc_url, enc_submit_url):
        if enc_url:
            url = self._decrypt(nonce64, base64.b64decode(enc_url))
        else:
            url = None
        if enc_submit_url:
            submit_url = self._decrypt(nonce64, base64.b64decode(
                enc_submit_url))
        else:
            submit_url = None
        LOG.debug('Searching for urls: %s and %s' % (url, submit_url))
        self._verify(nonce64, verifier64)
        entry = self._get_login(submit_url)
        if not entry:
            LOG.debug('No match for submit_url, trying url')
            entry = self._get_login(url)
        resp = {'RequestType': 'get-logins'}
        self._sign(resp)
        if not entry:
            LOG.debug('No match found')
            resp['Success'] = False
        else:
            LOG.debug('Found matching entry `%s\'' % entry.name())
            resp['Success'] = True
            resp['Entries'] = [self._make_entry(resp['Nonce'], entry)]
        return resp

    def get_logins_count(self, nonce64, verifier64, enc_url, enc_submit_url):
        resp = self.get_logins(nonce64, verifier64, enc_url, enc_submit_url)
        resp['RequestType'] = 'get-logins-count'
        if 'Entries' in resp:
            resp['Count'] = len(resp['Entries'])
            del resp['Entries']
        else:
            resp['Count'] = 0
        return resp


class KeePassHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = json.loads(self.rfile.read(length))

        LOG.debug('Request: %s' % data)
        rt = data.get('RequestType')
        if rt == 'test-associate':
            resp = self.server.context.test_associate(
                data.get('Nonce'),
                data.get('Verifier'),
                data.get('Id'))
        elif rt == 'associate':
            resp = self.server.context.associate(
                data.get('Nonce'),
                data.get('Verifier'),
                data.get('Key'))
        elif rt == 'get-logins':
            resp = self.server.context.get_logins(
                data.get('Nonce'),
                data.get('Verifier'),
                data.get('Url'),
                data.get('SubmitUrl'))
        elif rt == 'get-logins-count':
            resp = self.server.context.get_logins_count(
                data.get('Nonce'),
                data.get('Verifier'),
                data.get('Url'),
                data.get('SubmitUrl'))
        else:
            resp = {}

        LOG.debug('Response: %s' % resp)
        s = StringIO()
        s.write(json.dumps(resp))
        self.send_response(resp and 200 or 404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(s.tell()))
        self.end_headers()
        s.seek(0)
        self.wfile.write(s.read())

    def log_message(self, *args, **kwargs):
        return


class KeePassHTTPServer(BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, context):
        BaseHTTPServer.HTTPServer.__init__(self, server_address,
                                           KeePassHTTPRequestHandler)
        self.context = context
