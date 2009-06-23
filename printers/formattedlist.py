'''Logs every bad host in a plain text file in a user-defined format.

Use Python's string formatting to create flexible output formats
(spanning multiple lines per host, or putting all hosts on one line if
wanted).

'''
import logging
import sys

from printers import BasePrinter, simplelist

_logger = logging.getLogger('yabfd')

class Printer(simplelist.Printer):
    def __init__(self, name, format='%(host)s', **kwargs):
        super(Printer, self).__init__(name, **kwargs)
        self.frmt = format

    def __repr__(self):
        '''Not the real representation.'''
        return '<%s.Printer(%r, %r)>' % (__name__, self.destfile,
                self.frmt)

    def print_(self, host, till):
        self.outf.write(self.frmt % {'host': host, 'till': till} + self.nl)
