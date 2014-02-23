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

from optparse import OptionParser
import subprocess

import server

def parse_opts():
    op = OptionParser()
    op.add_option('-p', '--password', dest='password',
                  help='Password for database')
    op.add_option('-a', '--ask', dest='askpass', action='store_true',
                  default=False, help='Ask for password')
    op.add_option('-A', '--allow-associate', dest='allow_associate',
                  action='store_true', default=False,
                  help='Allow new associations')
    return op

def usage(op, error=None):
    op.print_help()
    if error:
        print "ERROR: %s" % error

if __name__ == '__main__':
    op = parse_opts()
    options, args = op.parse_args()
    if len(args) != 1:
        usage(op, 'A database must be specified')
        sys.exit(1)
    if options.askpass:
        p = subprocess.Popen(['/usr/libexec/openssh/ssh-askpass',
                              'KeePassX Database Password'],
                             stdout=subprocess.PIPE)
        passphrase = p.stdout.read().strip()
        p.wait()
    elif options.password:
        passphrase = options.password
    else:
        usage(op, 'Either -p or -a is required')
        sys.exit(1)

    kpctxt = server.KeePassHTTPContext(args[0], passphrase,
                                       allow_associate=options.allow_associate)
    httpd = server.KeePassHTTPServer(('127.0.0.1', 19455), kpctxt)
    httpd.serve_forever()
