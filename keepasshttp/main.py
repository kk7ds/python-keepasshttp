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

import ConfigParser
import logging
from optparse import OptionParser
import os
import subprocess
import sys

from keepasshttp import server
from keepasshttp import util

LOG = util.get_logger(__name__)


def parse_opts(defaults):
    def boolopt(k):
        return defaults.get(k, 'False') == 'True'

    def intopt(k):
        if k in defaults:
            return int(defaults[k])
        return None

    op = OptionParser()
    op.add_option('-p', '--password', dest='password',
                  help='Password for database')
    op.add_option('-a', '--ask', dest='askpass', action='store_true',
                  default=boolopt('askpass'),
                  help='Ask for password')
    op.add_option('-A', '--allow-associate', dest='allow_associate',
                  action='store_true',
                  default=boolopt('allow-associate'),
                  help='Allow new associations')
    op.add_option('-D', '--debug', dest='debug', action='store_true',
                  default=boolopt('debug'),
                  help='Enable debug logging')
    op.add_option('-l', '--logfile', dest='logfile',
                  default=defaults.get('logfile'),
                  help='Log filename')
    op.add_option('-d', '--daemon', dest='daemon', action='store_true',
                  default=boolopt('daemon'),
                  help='Start as a daemon')
    op.add_option('-t', '--timeout', dest='timeout', type='int',
                  default=intopt('timeout'),
                  metavar='MINUTES',
                  help='Require password on demand and this often')
    op.add_option('', '--save-config', dest='save_config',
                  action='store_true', default=False,
                  help='Save options to config file')
    op.add_option('', '--just-ask', dest='just_ask',
                  action='store_true', default=False,
                  help='Just ask for password and echo to stdout')
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
    password = tkSimpleDialog.askstring('Password', 'Database Password',
                                        show='*')
    return password


def ask_for_password():
    pashua_path = os.path.join(os.path.expanduser('~'),
                               'Applications', 'Pashua.app',
                               'Contents', 'MacOS', 'Pashua')
    if os.path.exists('/usr/bin/zenity'):
        LOG.debug('Prompting for password with Zenity')
        p = subprocess.Popen(['/usr/bin/zenity',
                              '--password', '--modal'],
                             stdout=subprocess.PIPE)
        passphrase = p.stdout.read().strip()
        p.wait()
    elif os.path.exists('/usr/bin/Xdialog'):
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
    elif os.path.exists(pashua_path):
        conf = """
*.title = KeePass Password

tf.type = password
tf.label = KeePass Password
tf.width = 300
"""
        p = subprocess.Popen([pashua_path, '-'],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        p.stdin.write(conf)
        p.stdin.close()
        result = p.stdout.read().strip()
        _, passphrase = result.split('=', 1)
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


def get_password(options=None):
    return ask_for_password()


def get_default_options(config):
    if not config.has_section('options'):
        return {}
    options = {}
    for option in config.options('options'):
        options[option] = config.get('options', option)
    return options


def main(cwd='.'):
    config = ConfigParser.ConfigParser()
    config.read(server.configfile_location())
    op = parse_opts(get_default_options(config))

    options, args = op.parse_args()
    if options.just_ask:
        print get_password()
        return

    if options.debug:
        util.set_log_level(logging.DEBUG)
    else:
        util.set_log_level(logging.INFO)
    if options.logfile:
        util.add_log_file(os.path.join(cwd, options.logfile))

    if (config.has_section('options') and
            config.has_option('options', 'database') and
            len(args) == 0):
        args = [config.get('options', 'database')]
    if len(args) != 1:
        usage(op, 'A database must be specified')
        sys.exit(1)

    if options.save_config:
        if not config.has_section('options'):
            config.add_section('options')
        for opt, val in options.__dict__.items():
            if getattr(options, opt):
                print "Setting %s=%s" % (opt, val)
                config.set('options', opt, val)
        config.set('options', 'database', args[0])
        with file(server.configfile_location(), 'w') as f:
            config.write(f)
        print "Saved options to config file"
        return

    while True:
        if options.password:
            if options.password == '-':
                password = sys.stdin.readline().strip()
            else:
                password = options.password
        elif options.timeout is None:
            password = get_password(options)
        else:
            password = get_password

        if not password:
            sys.exit(1)

        try:
            kpctxt = server.KeePassHTTPContext(
                args[0], password,
                allow_associate=options.allow_associate,
                timeout=options.timeout, config=config)
            break
        except ValueError:
            if options.password:
                LOG.error('Database password is incorrect')
                sys.exit(1)
            elif options.timeout is not None:
                LOG.error('Timeout-based initialization failed')
                sys.exit(1)

    httpd = server.KeePassHTTPServer(('127.0.0.1', 19455), kpctxt)
    LOG.debug('Starting server')
    LOG.debug('Config: %s' % options)
    httpd.serve_forever()
