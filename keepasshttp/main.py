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

import logging
from optparse import OptionParser
import os
import subprocess
import sys

from keepasshttp import server
from keepasshttp import util

LOG = util.get_logger(__name__)


def parse_opts():
    op = OptionParser()
    op.add_option('-p', '--password', dest='password',
                  help='Password for database')
    op.add_option('-a', '--ask', dest='askpass', action='store_true',
                  default=False, help='Ask for password')
    op.add_option('-A', '--allow-associate', dest='allow_associate',
                  action='store_true', default=False,
                  help='Allow new associations')
    op.add_option('-D', '--debug', dest='debug', action='store_true',
                  default=False, help='Enable debug logging')
    return op


def usage(op, error=None):
    op.print_help()
    if error:
        print "ERROR: %s" % error


def fallback_gui_password_prompt():
    import Tkinter
    import tkSimpleDialog
    root = Tkinter.Tk()
    root.withdraw()
    password = tkSimpleDialog.askstring('Password', 'Database Password')
    return password


def ask_for_password():
    if os.path.exists('/usr/bin/Xdialog'):
        LOG.debug('Prompting for password with Xdialog')
        p = subprocess.Popen(['/usr/bin/Xdialog',
                              '--password',
                              '--stdout',
                              '--inputbox',
                              'KeePassX Database Password',
                              '0', '50'],
                             stdout=subprocess.PIPE)
        passphrase = p.stdout.read().strip()
        p.wait()
    elif os.path.exists('/usr/libexec/openssh/ssh-askpass'):
        LOG.debug('Prompting for password with ssh-askpass')
        p = subprocess.Popen(['/usr/libexec/openssh/ssh-askpass',
                              'KeePassX Database Password'],
                             stdout=subprocess.PIPE)
        passphrase = p.stdout.read().strip()
        p.wait()
    else:
        LOG.debug('Prompting for password with Tk')
        try:
            passphrase = fallback_gui_password_prompt()
        except ImportError:
            LOG.warn('No UI askpass mechanism supported, trying console')
            print 'KeePassX Database Password: ',
            passphrase = sys.stdin.readline().strip()
            if not passphrase:
                LOG.error('No way to ask for the password!')
    return passphrase


def main():
    op = parse_opts()
    options, args = op.parse_args()
    if options.debug:
        util.set_log_level(logging.DEBUG)
    else:
        util.set_log_level(logging.INFO)
    if len(args) != 1:
        usage(op, 'A database must be specified')
        sys.exit(1)
    if options.askpass:
        passphrase = ask_for_password()
    elif options.password:
        passphrase = options.password
    else:
        usage(op, 'Either -p or -a is required')
        sys.exit(1)

    kpctxt = server.KeePassHTTPContext(args[0], passphrase,
                                       allow_associate=options.allow_associate)
    httpd = server.KeePassHTTPServer(('127.0.0.1', 19455), kpctxt)
    LOG.debug('Starting server')
    httpd.serve_forever()
