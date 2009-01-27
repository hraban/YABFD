import collections
import logging
import itertools

_logger = logging.getLogger('yabfd' + __name__)

class BaseParser(object):
    '''Baseclass for all parsers.

    Intended to be subclassed by at least implementing ._parse(log) for parsing
    a single logfile.

    '''
    def __init__(self):
        self._logs = collections.deque()
        _logger.debug('Created parser %s.', self)

    def load_logs(self, logs):
        self._logs.extend(logs)

    def parse(self):
        return itertools.chain(*(self._parse(log) for log in self._logs))
