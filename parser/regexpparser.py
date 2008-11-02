import collections
import logging
import re

from parser import BaseParser

_logger = logging.getLogger('yabfd' + __name__)

class Parser(BaseParser):
    def __init__(self, regexp, logfiles):
        super(Parser, self).__init__()
        self._r = re.compile(regexp)
        self._ips = []
        self.load_logs(e.strip() for e in logfiles.split(','))

    def __str__(self):
        return 'regexpparser'

    def _parse(self, log):
        _logger.debug('%s parsing %s.', self, log)
        hits = collections.defaultdict(lambda: 0)
        for l in open(log, 'r'):
            m = self._r.search(l)
            if m is not None:
                yield m.group('ip')
