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
import os
import re
import shutil
import sys

DEFAULT_IGNORE_PATH = '/usr/local/etc/yabfd.whitelist.txt'
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
    def __init__(self, backlog, ignore=None, bantime=7, threshold=10,
            output='-'):
        if output == '-':
            self.outf = sys.stdout
        else:
            self.outf = open(output, 'w')
        self.backlog = backlog
        if ignore is not None:
            self.ignores = parse_whitelist(ignore)
        else:
            self.ignores = frozenset()
        _logger.debug('Whitelist: %s', ', '.join(self.ignores) or 'empty')
        self.hits = collections.defaultdict(lambda: [0,
                                        datetime.date.fromtimestamp(0)])
        self.threshold = threshold
        self.bantime = datetime.timedelta(bantime)

    def _read_old_backlog(self):
        '''Returns True if the entire backlog was properly read.

        If an error occurs somewhere in the middle the data that was
        succesfully read is not discarded. Reading is, at this point, stopped,
        though, and False is returned.

        If the file does not exist True is returned. If it does exist but
        reading it fails False is returned.

        '''
        try:
            r = csv.reader(open(self.backlog, 'rb'))
        except IOError, e:
            if not os.path.exists(self.backlog):
                return True
            else:
                _logger.warning('Unable to read backlog (%s), continuing.', e)
                return False
        try:
            for (host, till) in r:
                # Parse the ISO 8601 format into a datetime.date object.
                tilld = datetime.datetime.strptime(till, '%Y-%m-%d').date()
                # Only overwrite latest offense read if backlog has even more
                # recent data.
                date = max(tilld - self.bantime, self.hits[host][1])
                self.hits[host] = [self.threshold, date]
        except ValueError, e:
            _logger.warning('Corrupt backlog (line %d: %s), continuing without'
                    ' reading the rest.', r.line_num, e)
            return False
        else:
            return True

    def done(self):
        '''Called when all hits are recorded.'''
        # Read all current bans.
        if not self._read_old_backlog():
            _logger.info('Reading backlog failed, saving old backlog as '
                                                ' "%s.corrupt".', self.backlog)
            shutil.move(self.backlog, self.backlog + '.corrupt')
        blw = csv.writer(open(self.backlog, 'wb'))
        for host, (numhits, date) in self.hits.iteritems():
            tilld = date + self.bantime
            # This number of failed login attempts is allowed:
            if (numhits < self.threshold or
                    # Whitelisted:
                    host in self.ignores or
                    # Most recent offense makes banning worthwile:
                    tilld < datetime.date.today()
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
        self._read_config(conffile)

    def _read_config(self, conffile):
        config = ConfigParser.SafeConfigParser(defaults={'ignore':
                DEFAULT_IGNORE_PATH})
        if not config.read(conffile):
            _logger.warning('Failed to read %s, skipping.', conffile)
        self._parsers = []
        for sec in (e for e in config.sections() if e.startswith('parser_')):
            ptype = config.get(sec, 'parser_type')
            config.remove_option(sec, 'parser_type')
            self.add_parser(ptype, dict(config.items(sec)))
        kwargs = dict(config.items('blacklist'))
        # Transform all integer values to `int`s.
        for opt in ('bantime', 'threshold'):
            if opt in kwargs:
                try:
                    kwargs[opt] = config.getint('blacklist', opt)
                except ValueError:
                    _logger.error('Invalid %s: "%s".', opt, kwargs[opt])
                    raise
        self._bl = Blacklist(**kwargs)

    def add_parser(self, parsertype, kwargs):
        p = getattr(__import__('parsers.' + parsertype),
                parsertype).Parser(**kwargs)
        self._parsers.append(p)

    def scan(self):
        for hit in itertools.chain(*(p.parse() for p in self._parsers)):
            self._bl.record(*hit)
        self._bl.done()

def parse_whitelist(fname):
    '''Parse a white-list (ignore) file.

    The syntax for this file is: one host per line, empty lines or lines
    starting with a hash (#) are ignored. The file must be encoded in ASCII.

    '''
    try:
        f = open(fname, 'r')
    except IOError, e:
        _logger.warning('Unable to open the whitelist (%s), continuing.', e)
        return frozenset()
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
