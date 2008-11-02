#!/usr/bin/env python
'''YABFD is Yet Another Brute Force Detector.

This program searches logfiles for hosts that are brute-forcing
passwords on a server through a daemon that allows remote login
(Postfix, OpenSSH, Dovecot, etc). It puts all found IP addresses in a
file that you can use to deny all access to all services from these
malignant hosts.

See <http://dan.drown.org/sbfd/> for the original script.

'''
import collections
import ConfigParser
import itertools
import logging
import optparse
import re
import sys

LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
LOGDATEFMT = '%c'

_logger = logging.getLogger('yabfd')

class Blacklist(object):
    def __init__(self, ignore, limit='5', output=None):
        if output is None:
            self.outf = sys.stdout
        else:
            self.outf = open(output, 'w')
        self.ignores = parse_whitelist(open(ignore, 'r'))
        _logger.debug('Whitelist: %s', ', '.join(self.ignores))
        self.hits = collections.defaultdict(lambda: 0)
        self.limit = int(limit)

    def done(self):
        '''Called when all hits are recorded.'''
        black = set(e[0] for e in self.hits.iteritems() if e[1] > self.limit)
        self.outf.writelines('%s\n' % e for e in black - self.ignores)
        self.outf.close()

    def record(self, ip):
        '''A failed login attempt from this IP has been found.'''
        self.hits[ip] += 1

class Scanner(object):
    def __init__(self, conffile):
        config = ConfigParser.SafeConfigParser()
        config.read(conffile)
        self._parsers = []
        for sec in (e for e in config.sections() if e.startswith('parser_')):
            ptype = config.get(sec, 'parser_type')
            config.remove_option(sec, 'parser_type')
            self.add_parser(ptype, dict(config.items(sec)))
        self._bl = Blacklist(**dict(config.items('blacklist')))

    def add_parser(self, parsertype, kwargs):
        p = getattr(__import__('parser.' + parsertype),
                parsertype).Parser(**kwargs)
        self._parsers.append(p)

    def scan(self):
        for hit in itertools.chain(*(p.parse() for p in self._parsers)):
            self._bl.record(hit)
        self._bl.done()

def parse_whitelist(f):
    '''Parse a white-list (ignore) file.

    The syntax for this file is: one host per line, empty lines or lines
    starting with a hash (#) are ignored. The file must be encoded in ASCII.

    '''
    return set(e for e in (l.strip() for l in f if l.strip()) if not
            e.startswith('#'))

def main():
    p = optparse.OptionParser()
    p.set_defaults(file='/usr/local/etc/yabfd.conf', loglevel=logging.WARNING)
    p.add_option('-f', '--file', help='use specified configuration file '
            '[default: %default]')
    p.add_option('-q', '--quiet', action='store_const', const=logging.ERROR,
            dest='loglevel', help='Only report severe errors.')
    p.add_option('-v', '--verbose', action='store_const', const=logging.INFO,
            dest='loglevel', help='Report informational messages.')
    p.add_option('-d', '--debug', action='store_const', const=logging.DEBUG,
            dest='loglevel', help='Report debugging info.')
    (options, args) = p.parse_args()
    logging.basicConfig(level=options.loglevel, format=LOGFORMAT,
            datefmt=LOGDATEFMT)
    s = Scanner(options.file)
    s.scan()

if __name__ == '__main__':
    main()
