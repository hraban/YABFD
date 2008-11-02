import collections
import datetime
import logging
import re
import time

from parser import BaseParser

_logger = logging.getLogger('yabfd' + __name__)

class Parser(BaseParser):
    def __init__(self, logfiles, datefrmt, datemodif="", **kwa):
        super(Parser, self).__init__()
        self._r = collections.deque(re.compile(v) for v in kwa.itervalues())
        self._ips = []
        self.load_logs(e.strip() for e in logfiles.split())
        self.datefrmt = datefrmt
        self.datemodif = datemodif

    def __str__(self):
        return 'regexpparser'

    def _parse(self, log):
        _logger.debug('%s parsing %s.', self, log)
        hits = collections.defaultdict(lambda: 0)
        for l in open(log, 'r'):
            for rex in self._r:
                m = rex.search(l)
                if m is None:
                    continue
                date = datetime.datetime.strptime(m.group('date'),
                        self.datefrmt).date()
                exec self.datemodif
                yield (date, m.group('host'))
                # No need to try other rexes on this line.
                break
