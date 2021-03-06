#!/usr/bin/env python
'''YABFD is Yet Another Brute Force Detector.

Copyright (c) 2008, 2009 Hraban Luyat

Search logfiles for hosts that are brute-forcing passwords on a server through
a daemon that allows remote login.

Inspired by Daniel Drown's SBFD: <http://dan.drown.org/sbfd/>.

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
try:
    import threading as _threading
except ImportError:
    import dummy_threading as _threading

LOGFORMAT = '%(asctime)s %(levelname)s: %(message)s'
LOGDATEFMT = None

_logger = logging.getLogger('yabfd')

class _BacklogError(StandardError):
    pass

class Blacklist(object):
    '''Track failed login hits from hosts and ban them when appropriate.

    Ignore is a whitelist file, bantime is the number of days violators will be
    banned, threshold is the number of failed login attempts after which a host
    will be banned, backlog is a logfile that yabfd uses internally to keep
    track of when hosts must be unbanned.

    '''
    def __init__(self, backlog, ignore=None, bantime=7, threshold=10):
        self.backlog = backlog
        if ignore is not None:
            self.ignores = parse_whitelist(ignore)
        else:
            self.ignores = frozenset()
        _logger.debug('Whitelist contains %d hosts.', len(self.ignores))
        self.hits = collections.defaultdict(lambda: [0,
                                        datetime.date.fromtimestamp(0)])
        self.threshold = threshold
        self.bantime = datetime.timedelta(bantime)
        # Acquired once by self.done().
        self._done_lock = _threading.Lock()

    def __iter__(self):
        # Just noting: this is not thread-safe. One thread acquires the lock for
        # testing, another thread tries the same thing at the same time but sees
        # it is unlocked and passes the conditional, the former thread now
        # releases the lock and raises the exception, but the second thread is
        # already writing to the backlog. Would require a lock-testing-lock :)
        if self._done_lock.acquire(False):
            self._done_lock.release()
            raise RuntimeError, "Call a Blacklist's done() before __iter__()."
        blw = csv.writer(open(self.backlog, 'wb'))
        for host, (numhits, date) in self.hits.iteritems():
            tilld = date + self.bantime
            # This number of failed login attempts is allowed:
            if (numhits >= self.threshold and
                    # Most recent offense makes banning worthwile:
                    tilld > datetime.date.today() # profile. bottleneck? cache!
                    ):
                blw.writerow((host, tilld.isoformat()))
                yield (host, tilld)

    def _read_old_backlog(self):
        '''Read the old bans and reapply them if appropriate.

        If an error occurs somewhere in the middle the data that was
        succesfully read is not discarded. Reading is, at this point, stopped,
        though, and a _BacklogError is raised.

        If the file does not exist no exception is raised. If it does exist but
        reading it fails a _BacklogError is raised.

        '''
        try:
            r = csv.reader(open(self.backlog, 'rb'))
        except IOError, e:
            if not os.path.exists(self.backlog):
                # File did not exist yet, do not propagate exception.
                return
            else:
                raise _BacklogError('I/O Error: %s, continuing.' % e)
        try:
            for (host, till) in r:
                # Parse the ISO 8601 format into a datetime.date object.
                tilld = datetime.datetime.strptime(till, '%Y-%m-%d').date()
                # Only overwrite latest offense read if backlog has even more
                # recent data.
                date = max(tilld - self.bantime, self.hits[host][1])
                self.hits[host] = [self.threshold, date]
        except ValueError, e:
            raise _BacklogError('Corrupt backlog (line %d: %s), continuing '
                    'without reading the rest.' % (r.line_num, e))
        else:
            _logger.info('Read %d hosts from backlog.', r.line_num)

    def done(self):
        '''Called when all hits are recorded.'''
        if not self._done_lock.acquire(False):
            raise RuntimeError, 'Blacklist.done() can only be called once.'
        # Read all current bans.
        try:
            self._read_old_backlog()
        except _BacklogError, e:
            _logger.error('Reading backlog failed: %s', e)
            _logger.warning('Saving old (corrupt) backlog as "%s.corrupt"',
                    self.backlog)
            shutil.move(self.backlog, self.backlog + '.corrupt')
        # Remove all whitelisted hosts from the hitlog.
        for ignore in self.ignores:
            self.hits.pop(ignore, None)
        del self.ignores
        _logger.debug('Blacklist is done processing.')

    def record(self, date, host, weight=1):
        '''A failed login attempt from this host has been found.

        The weight operand is a multiplier for the encountered hit. It allows
        the caller to make some hits more severe than others without calling
        record() repeatedly.

        '''
        h = self.hits[host]
        h[0] += weight
        h[1] = max(h[1], date)

class Scanner(object):
    '''Handles the scanning and parsing of a logfile to extract bad hosts.'''
    def __init__(self, conffile):
        self._parsers = []
        self._printers = []
        try:
            self._read_config(conffile)
        except Exception, e:
            _logger.error('Reading configuration at %r failed. Details: %r',
                    conffile, e)
            # Continue as a generic error (hide underlying details from error
            # reporting higher up).
            raise RuntimeError, ('Scanner had trouble reading the configuration'
                                ' file.')
        else:
            _logger.debug('Scanner read configuration at %r.', conffile)

    def _read_config(self, conffile):
        config = ConfigParser.SafeConfigParser()
        # Using open() manually here will cause an exception if the file can not
        # be opened. This is wanted, as opposed to config.read's (not readfp())
        # default behaviour of silently ignoring files that can not be opened.
        config.readfp(open(conffile))
        for sec in config.sections():
            if sec.startswith('parser_'):
                ptype = config.get(sec, 'parser_type')
                config.remove_option(sec, 'parser_type')
                kwargs = dict(config.items(sec))
                kwargs['name'] = sec[7:]
                self.add_parser(ptype, kwargs)
            elif sec.startswith('printer_'):
                ptype = config.get(sec, 'printer_type')
                config.remove_option(sec, 'printer_type')
                kwargs = dict(config.items(sec))
                kwargs['name'] = sec[8:]
                self.add_printer(ptype, kwargs)
        kwargs = dict(config.items('blacklist'))
        # Transform all integer values to `int`s.
        for opt in ('bantime', 'threshold'):
            if opt in kwargs:
                try:
                    kwargs[opt] = config.getint('blacklist', opt)
                except ValueError:
                    _logger.error('Invalid %s: %r.', opt, kwargs[opt])
                    raise
        self._bl = Blacklist(**kwargs)

    def add_parser(self, parsertype, kwargs):
        p = getattr(__import__('parsers.' + parsertype),
                parsertype).Parser(**kwargs)
        self._parsers.append(p)

    def add_printer(self, printertype, kwargs):
        p = getattr(__import__('printers.' + printertype),
                printertype).Printer(**kwargs)
        self._printers.append(p)

    def scan(self):
        '''Parse and process all logfiles.
        
        If an error occurs with one of the printers, it is logged, then ignored
        while the other printers try to finish and finally re-raised at the end.
        
        '''
        error = None
        for p in self._parsers:
            for hit in p.parse():
                self._bl.record(*hit)
        self._bl.done()
        # Apply all output handlers to every blacklist entry.
        for entry in self._bl:
            _logger.info('Banning %s until %s.', entry[0], entry[1])
            for printer in self._printers:
                try:
                    printer.print_(*entry)
                except Exception, e:
                    _logger.error('Printer %s could not print %r. Details: %r',
                            printer, entry, e)
                    error = 'One or more printjobs failed.'
        # Clean up printers (as much as possible).
        for printer in self._printers:
            try:
                printer.close()
            except Exception, e:
                _logger.error('Closing printer %s failed. Details: %r', printer,
                        e)
                # Yes, this will override the other error, but the logs are OK.
                error = 'One or more printers did not close properly.'
        del self._printers
        if error is not None:
            raise RuntimeError, error

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
    old_help = p.print_help
    def my_help():
        '''Print introduction before help message.'''
        print __doc__
        old_help()
    p.print_help = my_help
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
    p.destroy()
    logging.basicConfig(level=options.loglevel, format=LOGFORMAT,
            datefmt=LOGDATEFMT)
    if options.loglevel <= logging.INFO:
        print >> sys.stderr, __doc__
    try:
        s = Scanner(options.file)
    except Exception, e:
        _logger.error('Creating the scanner failed, aborting. Details: %r', e)
        sys.exit('Aborting operation.')
    try:
        s.scan()
    except Exception, e:
        _logger.error('Scanner crashed half-way through. Details: %r', e)
        sys.exit('Halting operation.')

if __name__ == '__main__':
    main()
