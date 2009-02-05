import collections
import logging
import itertools

_logger = logging.getLogger('yabfd.' + __name__)

class BaseParser(object):
    '''Baseclass for all parsers.

    Intended to be subclassed by at least implementing ._parse(log) for parsing
    a single logfile.

    '''
    def __init__(self, name):
        self._logs = collections.deque()
        self.name = name
        _logger.debug('Created parser %s.', self)

    def __str__(self):
        return 'parser_' + self.name

    def load_logs(self, logs):
        self._logs.extend(logs)

    def parse(self):
        return itertools.chain(*(self._parse(log) for log in self._logs))
