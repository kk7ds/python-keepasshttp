
from keepass import kpdb

class KeePassUtil(object):
    def _reload(self):
        self._db = kpdb.Database(self._db_file,
                                 self._db_pass)
        self._root = self._db.hierarchy()

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
        return self._find_by_attr(self._root, url=url)
