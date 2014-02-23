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

import os

from keepass import kpdb

class KeePassUtil(object):
    def _reload(self):
        self._db = kpdb.Database(self._db_file,
                                 self._db_pass)
        self._root = self._db.hierarchy()
        self._db_mtime = os.path.getmtime(self._db_file)

    def _check_reload(self):
        current_mtime = os.path.getmtime(self._db_file)
        if current_mtime > self._db_mtime:
            print 'Reloading database due to change'
            self._reload()

    def __init__(self, db_file, db_pass):
        self._db_file = db_file
        self._db_pass = db_pass
        self._reload()

    def _find_by_attr(self, node, **kwargs):
        def is_match(entry):
            for key in kwargs:
                attr = getattr(entry, key)
                value = attr
                if value != kwargs[key]:
                    return False
            return True

        for entry in node.entries:
            if is_match(entry):
                return entry
        for node in node.nodes:
            entry = self._find_by_attr(node, **kwargs)
            if entry:
                return entry
        return None

    def find_entry_by_url(self, url):
        self._check_reload()
        return self._find_by_attr(self._root, url=url)
