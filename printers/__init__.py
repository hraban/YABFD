'''Printers take care of logging the blacklist somewhere.

This can be a plain text file in whatever syntax, a TCP logger, a UNIX pipe, a
tts reader, etc. To create a printer, put it in its own file and call it
`Printer'.

'''
import logging

_logger = logging.getLogger('yabfd.' + __name__)

class BasePrinter(object):
    def __init__(self, name):
        self.name = name
        _logger.debug('Created %s.', self)

    def __str__(self):
        return 'printer_' + self.name

    def close(self):
        '''Called when all printing is done.'''
        _logger.debug('Closing printer %s.', self)

    def print_(self, badhost, banned_till):
        raise NotImplementedError
