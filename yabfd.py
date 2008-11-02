#!/usr/bin/env python
'''YABFD is Yet Another Brute Force Detector.

Copyright (c) 2008 Hraban Luyat

Search logfiles for hosts that are brute-forcing passwords on a server through
a daemon that allows remote login.

Inspired by SBFD: <http://dan.drown.org/sbfd/>.

'''
import collections
import ConfigParser
import csv
import datetime
import itertools
import logging
import optparse
import re
import sys

LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
LOGDATEFMT = '%c'

_logger = logging.getLogger('yabfd')

class Blacklist(object):
    '''Track failed login hits from hosts and ban them when appropriate.

    Ignore is a whitelist file, bantime is the number of days violators will be
    banned, threshold is the number of failed login attempts after which a host
    will be banned, backlog is a logfile that yabfd uses internally to keep
    track of when hosts must be unbanned, output is a file where all violators
    will be written to, seperated by newlines.

    '''
    def __init__(self, ignore, backlog, bantime='7', threshold='10',
            output=None):
        if output is None or output == '-':
            self.outf = sys.stdout
        else:
            self.outf = open(output, 'w')
        self.backlog = backlog
        self.ignores = parse_whitelist(open(ignore, 'r'))
        _logger.debug('Whitelist: %s', ', '.join(self.ignores))
        self.hits = collections.defaultdict(lambda: [0,
                                        datetime.date.fromtimestamp(0)])
        self.threshold = int(threshold)
        self.bantime = datetime.timedelta(int(bantime))

    def done(self):
        '''Called when all hits are recorded.'''
        # Read all current bans.
        try:
            for host, till in csv.reader(open(self.backlog, 'rb')):
                # Parse the ISO 8601 format into a datetime.date object.
                tilld = datetime.datetime.strptime(till, '%Y-%m-%d').date()
                self.hits[host] = (self.threshold, tilld - self.bantime)
        except IOError, e:
            _logger.warning('Unable to read backlog (%s), continuing.', e)
        blw = csv.writer(open(self.backlog, 'wb'))
        for host, (numhits, date) in self.hits.iteritems():
            tilld = date + self.bantime
            if (numhits < self.threshold or
                    # This number of failed login attempts is allowed.
                    host in self.ignores or
                    # Whitelisted.
                    tilld < datetime.date.today()
                    # Most recent offense makes banning worthwile.
                    ):
                continue
            till = tilld.isoformat()
            _logger.info('Banning %s until %s.', host, till)
            self.outf.write(host + '\n')
            blw.writerow((host, till))
        self.outf.close()
        _logger.debug('%s done.', self)

    def record(self, date, host):
        '''A failed login attempt from this host has been found.'''
        h = self.hits[host]
        h[0] += 1
        h[1] = max(h[1], date)

class Scanner(object):
    def __init__(self, conffile):
        config = ConfigParser.SafeConfigParser()
        if not config.read(conffile):
            _logger.warning('Failed to read %s, skipping.', conffile)
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
            self._bl.record(*hit)
        self._bl.done()

def parse_whitelist(f):
    '''Parse a white-list (ignore) file.

    The syntax for this file is: one host per line, empty lines or lines
    starting with a hash (#) are ignored. The file must be encoded in ASCII.

    '''
    return frozenset(e for e in (l.strip() for l in f if l.strip()) if not
            e.startswith('#'))

def main():
    p = optparse.OptionParser()
    p.set_defaults(file='/usr/local/etc/yabfd.conf', loglevel=logging.WARNING)
    p.add_option('-f', '--file', help='use specified configuration file '
            '[default: %default]')
    p.add_option('-q', '--quiet', action='store_const', const=logging.ERROR,
            dest='loglevel', help='only report critical errors')
    p.add_option('-v', '--verbose', action='store_const', const=logging.INFO,
            dest='loglevel', help='print informational messages')
    p.add_option('-d', '--debug', action='store_const', const=logging.DEBUG,
            dest='loglevel', help='print debugging info')
    (options, args) = p.parse_args()
    logging.basicConfig(level=options.loglevel, format=LOGFORMAT,
            datefmt=LOGDATEFMT)
    if options.loglevel <= logging.INFO:
        print >> sys.stderr, __doc__
    s = Scanner(options.file)
    s.scan()

if __name__ == '__main__':
    main()
