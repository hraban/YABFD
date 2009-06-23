import csv
from datetime import datetime as dt
import logging
import sys

from parsers import BaseParser

_logger = logging.getLogger('yabfd.' + __name__)

class Parser(BaseParser):
    def __init__(self, name, blacklist, bandate=dt.max, hitweight=sys.maxint):
        super(Parser, self).__init__(name)
        self.load_logs([blacklist])
        self.weight = hitweight
        self.date = bandate

    def _parse(self, blacklist):
        _logger.debug('%s reading %r.', self, blacklist)
        r = csv.reader(open(blacklist, 'rb'))
        for row in r:
            try:
                host = row.pop(0)
            except ValueError:
                _logger.error('Blacklist %r malformed at line %d, skipping.',
                        blacklist, r.line_num)
                continue
            date = dt.strptime(row.pop(0), '%Y-%m-%d').date() if row else dt.max
            weight = int(row.pop(0)) if row else self.weight
            yield (date, host, weight)
        _logger.debug('%s read %d hosts from %r.', self, r.line_num, blacklist)
