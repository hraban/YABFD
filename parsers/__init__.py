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

    def _parse(self, log):
        '''Return an iterable that contains all hits found in this logfile.

        A hit is a two- or three-element iterable of the following form:

        0: datetime.date: The day the hit took place.
        1: str: The offending host.
        2: (opt) The weight of the hit. An integer, where 1 is normal, 0 means
           an insignificant hit. Negative numbers mean that the host should be
           less distrusted (e.g.: it entered a correct password somewhere).

        In fact, this iterable is unpacked and directly passed to
        Blacklist.record() (yabfd.py), which is defined as:
            def record(self, date, host, weight=1)
        but this is subject to change.

        '''
        pass

    def parse(self):
        return itertools.chain(*(self._parse(log) for log in self._logs))
