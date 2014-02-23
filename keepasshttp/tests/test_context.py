from Crypto.Cipher import AES
import base64
import mock
import unittest

from keepasshttp import server


TEST_KEY = '0123456789ABCDEF'
TEST_IV = '----------------'


def fake_config_get(section, key):
    if key == 'key':
        return base64.b64encode(TEST_KEY)
    elif key == 'ident':
        return 'bar'
    else:
        raise Exception('Bad key %s' % key)


class TestContext(unittest.TestCase):
    @mock.patch('keepasshttp.util.KeePassUtil')
    @mock.patch('ConfigParser.ConfigParser')
    def setUp(self, config, fake_util):
        super(TestContext, self).setUp()
        self.context = server.KeePassHTTPContext('fake', 'fake')
        self.context._config.get.side_effect = fake_config_get

    def test_key_property(self):
        self.assertEqual(TEST_KEY, self.context.key)

    def test_ident_property(self):
        self.context._config.has_option.return_value = True
        self.assertEqual('bar', self.context.ident)
        self.context._config.has_option.assert_called_once_with('general',
                                                                'ident')

    def test_ident_property_not_exists(self):
        self.context._config.has_option.return_value = False
        with mock.patch.object(self.context, '_save_config') as save:
            self.assertEqual('bar', self.context.ident)
            save.assert_called_once_with()
        self.context._config.has_option.assert_called_once_with('general',
                                                                'ident')
        self.context._config.get.assert_called_once_with('general', 'ident')
        self.context._config.set.assert_called_once_with('general', 'ident',
                                                         'Default')

    def test_verify(self):
        key64 = base64.b64encode(TEST_KEY)
        nonce64 = base64.b64encode(TEST_IV)
        aes = AES.new(TEST_KEY, AES.MODE_CBC, TEST_IV)
        cipertext = aes.encrypt(server.aes_pad(nonce64))
        verifier64 = base64.b64encode(cipertext)
        self.assertTrue(self.context._verify(nonce64, verifier64, key64))

    def test_verify_stored_key(self):
        key64 = base64.b64encode(TEST_KEY)
        nonce64 = base64.b64encode(TEST_IV)
        aes = AES.new(TEST_KEY, AES.MODE_CBC, TEST_IV)
        cipertext = aes.encrypt(server.aes_pad(nonce64))
        verifier64 = base64.b64encode(cipertext)
        self.assertTrue(self.context._verify(nonce64, verifier64))

    @mock.patch('keepasshttp.server.new_iv')
    def test_sign(self, new_iv):
        key64 = base64.b64encode(TEST_KEY)
        new_iv.return_value = TEST_IV
        nonce64 = base64.b64encode(TEST_IV)
        aes = AES.new(TEST_KEY, AES.MODE_CBC, TEST_IV)
        verifier64 = base64.b64encode(aes.encrypt(server.aes_pad(nonce64)))
        resp = {}
        self.context._sign(resp)
        self.assertEqual(resp['Nonce'], nonce64)
        self.assertEqual(resp['Verifier'], verifier64)
        self.assertEqual(resp['Version'], '2.0.0.0')
        self.assertEqual(resp['Id'], 'bar')

    @mock.patch('Crypto.Cipher.AES')
    def test_encrypt(self, aes):
        aes_obj = mock.MagicMock()
        aes.new.return_value = aes_obj
        aes_obj.encrypt.return_value = 'ciphertext'
        result = self.context._encrypt(base64.b64encode(TEST_IV), 'foo')
        aes.new.assert_called_once_with(TEST_KEY, aes.MODE_CBC, TEST_IV)
        self.assertEqual(base64.b64encode('ciphertext'), result)

    @mock.patch('Crypto.Cipher.AES')
    def test_decrypt(self, aes):
        aes_obj = mock.MagicMock()
        aes.new.return_value = aes_obj
        aes_obj.decrypt.return_value = 'plaintext'
        result = self.context._decrypt(base64.b64encode(TEST_IV), 'foo')
        aes.new.assert_called_once_with(TEST_KEY, aes.MODE_CBC, TEST_IV)
        self.assertEqual('plaintext', result)

    def test_test_associate_no_ident(self):
        self.assertFalse(self.context._test_associate('foo', 'bar', None))

    def test_test_associate_no_key(self):
        self.context._config.get.has_option.return_value = False
        self.assertFalse(self.context._test_associate('foo', 'bar', 'baz'))

    def test_test_associate_bad_ident(self):
        self.assertFalse(self.context._test_associate('foo', 'bar', 'baz'))

    def test_test_associate_verify_called(self):
        with mock.patch.object(self.context, '_verify') as verify:
            verify.return_value = 'verify-call'
            self.assertEqual('verify-call',
                             self.context._test_associate('foo', 'bar', 'bar'))

    def test_test_associate_success(self):
        with mock.patch.object(self.context, '_test_associate') as ta:
            with mock.patch.object(self.context, '_sign') as sign:
                ta.return_value = True
                resp = self.context.test_associate('foo', 'bar', 'baz')
                self.assertEqual(1, sign.call_count)
                ta.assert_called_once_with('foo', 'bar', 'baz')
        self.assertEqual({'RequestType': 'test-associate',
                          'Id': self.context.ident,
                          'Success': True},
                         resp)

    def test_test_associate_failed(self):
        with mock.patch.object(self.context, '_test_associate') as ta:
            with mock.patch.object(self.context, '_sign') as sign:
                ta.return_value = False
                resp = self.context.test_associate('foo', 'bar', 'baz')
                self.assertEqual({}, resp)

    def test_associate_not_allowed(self):
        self.context._allow_associate = False
        resp = self.context.associate('foo', 'bar', 'baz')
        self.assertFalse(resp['Success'])

    def test_associate_verify_failed(self):
        self.context._allow_associate = True
        with mock.patch.object(self.context, '_verify') as verify:
            verify.return_value = False
            resp = self.context.associate('foo', 'bar', 'baz')
        self.assertFalse(resp['Success'])

    def test_associate_verify_success(self):
        key64 = base64.b64encode(TEST_KEY)
        self.context._allow_associate = True
        with mock.patch.object(self.context, '_verify') as verify:
            with mock.patch.object(self.context, '_sign') as sign:
                with mock.patch.object(self.context, '_save_config') as save:
                    verify.return_value = True
                    resp = self.context.associate('foo', 'bar', key64)
                    self.assertEqual(1, sign.call_count)
                    self.assertEqual(1, save.call_count)
        self.assertTrue(resp['Success'])
        self.context._config.set.assert_called_once_with('general',
                                                         'key', key64)
        self.assertTrue(resp['Success'])

    def test_make_entry(self):
        entry = mock.MagicMock()
        entry.username = 'user'
        entry.password = 'pass'
        entry.name = 'name'
        entry.uuid = 'uuid'

        def fake_encrypt(nonce, data):
            self.assertEqual('nonce', nonce)
            return 'encrypted-%s' % data

        with mock.patch.object(self.context, '_encrypt', new=fake_encrypt):
            encentry = self.context._make_entry('nonce', entry)

        self.assertEqual({'Login': 'encrypted-user',
                          'Password': 'encrypted-pass',
                          'Name': 'encrypted-name',
                          'Uuid': 'encrypted-uuid'},
                         encentry)

    def test_get_logins(self):
        def fake_decrypt(nonce, data):
            self.assertEqual('foo', nonce)
            return data

        def fake_find_by_url(url):
            if url == 'url':
                return url

        def fake_sign(resp):
            resp['Nonce'] = 'nonce'

        self.context._db_util.find_entry_by_url.side_effect = fake_find_by_url

        @mock.patch.object(self.context, '_verify')
        @mock.patch.object(self.context, '_sign')
        @mock.patch.object(self.context, '_decrypt')
        @mock.patch.object(self.context, '_make_entry')
        def do_test(make_entry, decrypt, sign, verify):
            decrypt.side_effect = fake_decrypt
            make_entry.return_value = 'entry'
            verify.return_value = True
            sign.side_effect = fake_sign
            resp = self.context.get_logins('foo', 'bar',
                                           base64.b64encode('url'),
                                           base64.b64encode('suburl'))
            verify.assert_called_once_with('foo', 'bar')
            self.assertEqual(1, sign.call_count)
            return resp

        resp = do_test()
        self.assertEqual(2, self.context._db_util.find_entry_by_url.call_count)
        self.assertTrue(resp['Success'])
        self.assertEqual('get-logins', resp['RequestType'])
        self.assertEqual(1, len(resp['Entries']))
        self.assertEqual('entry', resp['Entries'][0])


class TestAESUtils(unittest.TestCase):
    def test_aes_pad(self):
        data = '0123456789ABCDE'
        self.assertEqual('%s\x01' % data,
                         server.aes_pad(data))

    def test_aes_pad_even(self):
        data = '0123456789ABCDEF'
        self.assertEqual('%s%s' % (data, '\x10' * 16),
                         server.aes_pad(data))

    def test_aes_unpad(self):
        data = '01234567890ABCDE\x01'
        self.assertEqual(data[:-1],
                         server.aes_unpad(data))
