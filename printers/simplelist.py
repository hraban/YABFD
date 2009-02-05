'''Logs every bad host on a single line in a plain text file.

Can be included by /etc/hosts.deny and Squid, for example.

'''
import sys

from printers import BasePrinter

class Printer(BasePrinter):
    def __init__(self, name, destfile='-', newline='\n'):
        super(Printer, self).__init__(name)
        if destfile == '-':
            self.outf = sys.stdout
        else:
            self.outf = open(destfile, 'wt')
        self.destfile = destfile
        self.nl = newline

    def __repr__(self):
        return '%s.Printer(%r, %r)' % (__name__, self.destfile, self.nl)

    def close(self):
        super(Printer, self).close()
        self.outf.close()

    def print_(self, host, till):
        self.outf.write(str(host) + self.nl)
