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
import os

from keepass import kpdb

FORMAT = '%(asctime)19.19s %(name)-10.10s %(levelname)s %(message)s'


class KeePassUtil(object):
    def _reload(self):
        LOG.debug('Loading %s' % self._db_file)
        self._db = kpdb.Database(self._db_file,
                                 self._db_pass)
        self._root = self._db.hierarchy()
        self._db_mtime = os.path.getmtime(self._db_file)

    def _check_reload(self):
        current_mtime = os.path.getmtime(self._db_file)
        if current_mtime > self._db_mtime:
            LOG.info('Detected database change')
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


ALL_LOGGERS = []


def get_logger(name):
    name = name.split('.')[-1]
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=FORMAT))
    logger.addHandler(handler)
    logger.setLevel(logging.CRITICAL)
    ALL_LOGGERS.append(logger)
    return logger


def add_logger_file(logger, filename):
    handler = logging.FileHandler(filename=filename)
    handler.setFormatter(logging.Formatter(fmt=FORMAT))
    logger.addHandler(handler)
    return handler


def set_log_level(level):
    for logger in ALL_LOGGERS:
        logger.setLevel(level)


LOG = get_logger(__name__)
