import collections
import datetime
import logging
import re
import time

from parsers import BaseParser

_logger = logging.getLogger('yabfd.' + __name__)

class Parser(BaseParser):
    def __init__(self, logfiles, name, datefrmt, datemodif="", **kwa):
        super(Parser, self).__init__(name)
        self._r = collections.deque(re.compile(v) for v in kwa.itervalues())
        self._ips = []
        self.logfiles = logfiles
        self.kwargs = kwa
        self.load_logs(e.strip() for e in logfiles.split() if e.strip())
        self.datefrmt = datefrmt
        self.datemodif = datemodif

    def _parse(self, log):
        _logger.debug('%s parsing %r.', self, log)
        for l in open(log, 'r'):
            for rex in self._r:
                m = rex.search(l)
                if m is None:
                    continue
                date = datetime.datetime.strptime(m.group('date'),
                        self.datefrmt).date()
                exec(self.datemodif)
                yield (date, m.group('host'))
                # No need to try other rexes on this line.
                break
        _logger.debug('%s done parsing %r.', self, log)
