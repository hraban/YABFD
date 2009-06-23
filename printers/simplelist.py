'''Logs every bad host on a single line in a plain text file.

Can be included by /etc/hosts.deny and Squid, for example.

'''
import logging
import sys

from printers import BasePrinter

_logger = logging.getLogger('yabfd')

class Printer(BasePrinter):
    def __init__(self, name, destfile='-', newline=r'\n'):
        super(Printer, self).__init__(name)
        if destfile == '-':
            self.outf = sys.stdout
        else:
            try:
                self.outf = open(destfile, 'wt')
            except IOError, e:
                _logger.error('Error while opening the file to save the ban-list'
                              ' to. Details: %r', e)
                # Continue as a generic error.
                raise RuntimeError, 'Banlist can not be saved.'
        self.destfile = destfile
        self.nl = eval('"%s"' % newline)

    def __repr__(self):
        return '%s.Printer(%r, %r)' % (__name__, self.destfile, self.nl)

    def close(self):
        super(Printer, self).close()
        self.outf.close()

    def print_(self, host, till):
        self.outf.write(str(host) + self.nl)
