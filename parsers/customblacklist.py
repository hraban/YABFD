import csv
import datetime
import logging
import sys

from parsers import BaseParser

_logger = logging.getLogger('yabfd.' + __name__)

class Parser(BaseParser):
    def __init__(self, name, blacklist, hitweight=sys.maxint):
        super(Parser, self).__init__(name)
        self.load_logs([blacklist])
        self.weight = hitweight

    def _parse(self, blacklist):
        _logger.debug('%s reading %r.', self, blacklist)
        r = csv.reader(open(blacklist, 'rb'))
        for row in r:
            try:
                host, date = row
            except ValueError:
                _logger.error('Blacklist %r malformed at line %d, continuing '
                                    'without the rest.', blacklist, r.line_num)
                return
            yield (datetime.datetime.strptime(date, '%Y-%m-%d').date(), host,
                    self.weight)
        _logger.debug('%s read %d hosts from %r.', self, r.line_num, blacklist)
