import datetime
import mock
import unittest

from keepasshttp import util


class KeePassUtilTest(unittest.TestCase):
    def setUp(self):
        super(KeePassUtilTest, self).setUp()
        self.util = util.KeePassUtil('file')

    def test_unlock(self):
        with mock.patch.object(self.util, '_reload') as r:
            self.util.unlock('password')
            r.assert_called_once_with('password')
        self.assertEqual('password', self.util._db_pass)
        self.assertEqual(None, self.util._expiration)

    def test_unlock_timeout(self):
        with mock.patch.object(self.util, '_reload') as r:
            self.util.unlock('password', timeout=1)
            r.assert_called_once_with('password')
        self.assertEqual('password', self.util._db_pass)
        self.assertTrue(isinstance(self.util._expiration,
                                   datetime.datetime))

    @mock.patch('datetime.datetime')
    def test_check_locked_expired(self, dt):
        dt.now.return_value = 10
        self.util._expiration = 1
        self.assertRaises(util.DatabaseLockedError,
                          self.util._check_locked)

    @mock.patch('datetime.datetime')
    def test_check_locked_not_expired(self, dt):
        dt.now.return_value = 1
        self.util._expiration = 10
        self.util._check_locked()

    def test_check_locked_no_expiration(self):
        self.util._check_locked()
