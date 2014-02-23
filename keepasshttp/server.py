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
from ConfigParser import ConfigParser
from Crypto.Cipher import AES
from Crypto import Random
from SimpleHTTPServer import SimpleHTTPRequestHandler
from StringIO import StringIO
import base64
import json
import os
import sys
import uuid

from keepasshttp import util

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

def configfile_location():
    return os.path.join(os.getenv('HOME', '.'),
                        '.keepasshttp')

class KeePassHTTPContext(object):
    def __init__(self, db_file, db_pass, allow_associate=False):
        self._db_util = util.KeePassUtil(db_file, db_pass)
        self._config = ConfigParser()
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
        if not self._allow_associate:
            print 'Refused to Associate (disabled)'
            resp['Success'] = False
            resp['Error'] = 'Association is disabled'
            return resp
        if not self._verify(nonce64, verifier64, key64):
            print "Failed verification for Associate"
            resp['Success'] = False
            resp['Error'] = 'Key verification failed'
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
        if not entry:
            entry = self._db_util.find_entry_by_url(url)
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

class KeePassHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = json.loads(self.rfile.read(length))

        rt = data['RequestType']
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

class KeePassHTTPServer(BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, context):
        BaseHTTPServer.HTTPServer.__init__(self, server_address,
                                           KeePassHTTPRequestHandler)
        self.context = context

