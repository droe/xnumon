#!/usr/bin/env python3
# vim: set list et ts=8 sts=4 sw=4 ft=python:

#-
# xnumon - monitor macOS for malicious activity
# https://www.roe.ch/xnumon
#
# Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
# All rights reserved.
#
# Licensed under the Open Software License version 3.0.

import datetime
import hashlib
import json
import subprocess
import sys
import time

import haklib.dt

def colour(code, text, extra=''):
    return '\x1b[38;5;%i%sm%s\x1b[0m' % (code, extra, text)

def brightwhite(text):
    return colour(15, text, extra=';1')

def red(text):
    return colour(9, text)

def green(text):
    return colour(10, text)

def yellow(text):
    return colour(11, text)

class Logs:
    def __init__(self, logfilepath, begin=None, end=None):
        self._records_by_eventcode = []
        with open(logfilepath, 'r') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except:
                    continue
                if 'time' not in obj:
                    continue
                t = haklib.dt.fromiso8601(obj['time'])
                if begin and t < begin:
                    continue
                if end and t > end:
                    continue
                if 'eventcode' not in obj:
                    continue
                ec = int(obj['eventcode'])
                while len(self._records_by_eventcode) < ec + 1:
                    self._records_by_eventcode.append([])
                obj['_raw'] = line.rstrip()
                self._records_by_eventcode[ec].append(obj)

    def __len__(self):
        count = 0
        for l in self._records_by_eventcode:
            count += len(l)
        return count

    def _compare(self, a, b):
        if isinstance(a, int):
            b = int(b)
        elif isinstance(a, (list, tuple)):
            b = b.split(',')
        if a != b:
            return False
        return True

    def _value_for_key(self, record, key):
        node = record
        for subkey in key.split('.'):
            if subkey not in node:
                return None
            node = node[subkey]
        return node

    def _test_conditions(self, record, conditions, ex, verbose=False):
        for key, value in conditions:
            have_value = self._value_for_key(record, key)
            if not have_value:
                if verbose:
                    print("record does not have key %s" % key)
                return False
            if value == '*':
                if key.endswith('.sha256'):
                    value = ex.sha256
                elif key.endswith('.sha1'):
                    value = ex.sha1
                elif key.endswith('.md5'):
                    value = ex.md5
            if not self._compare(have_value, value):
                if verbose:
                    print("%s: %s != %s" % (key, have_value, value))
                return False
            else:
                if verbose:
                    print("%s: %s == %s" % (key, have_value, value))
        return True

    def find(self, eventcode, conditions, ex, verbose=False, debug=False):
        if len(self._records_by_eventcode) < eventcode + 1:
            if verbose:
                print("no log records with eventcode=%i" % eventcode)
            return []
        matching_records = []
        for record in self._records_by_eventcode[eventcode]:
            if debug:
                print(repr(record['_raw']))
            if self._test_conditions(record, conditions, ex, verbose=verbose):
                matching_records.append(record)
        return matching_records

class Specs:
    class Spec:
        _EVENTMAP = {
            'xnumon-ops':     0,
            'xnumon-stats':   1,
            'image-exec':     2,
            'process-access': 3,
            'launchd-add':    4,
            'socket-bind':    5,
            'socket-accept':  6,
            'socket-connect': 7,
        }
        def __init__(self, spec):
            parts = spec.strip().split(' ')
            header = parts[0].split(':')
            if 'absent' in header[-2]:
                self._wanted = 0
            else:
                self._wanted = 1
            self._spectype = header[-1]
            if self._spectype != 'testcase':
                self._eventcode = self._EVENTMAP[self._spectype]
            self._conditions = [part.split('=') for part in parts[1:]]
            self._spec = spec

        def check(self, ex, logs, verbose=False, debug=False):
            if self._spectype == 'testcase':
                for key, value in self._conditions:
                    if key == 'returncode':
                        if ex.returncode != int(value):
                            print("expected returncode %s but have %i:" % (
                                  value, ex.returncode))
                            print(ex.stderr or "(no stderr)")
                            return False
                    else:
                        print(yellow("error") + ": unknown condition %s=%s" % (
                              key, value))
                        return False
                return True
            results = logs.find(self._eventcode, self._conditions, ex,
                                verbose=verbose, debug=debug)
            if verbose:
                print("%i matching records" % len(results))
            return len(results) == self._wanted

        def __str__(self):
            return self._spec

    def __init__(self, specs):
        self._specs = [self.Spec(spec) for spec in specs]

    def check(self, ex, logs, verbose=False, debug=False):
        result = True
        for spec in self._specs:
            if verbose:
                print("testing %s" % spec)
            if not spec.check(ex, logs, verbose=verbose, debug=debug):
                print("failed  %s" % spec)
                result = False
            else:
                print("success %s" % spec)
        return result

class TestRunner:
    class Run:
        def __init__(self, argv, timeout=None):
            self.path = argv[0]
            if self.path == 'sudo':
                self.path = argv[2]
            with open(self.path, 'rb') as f:
                buf = f.read()
                self.sha256 = hashlib.sha256(buf).hexdigest()
                self.sha1   = hashlib.sha1(buf).hexdigest()
                self.md5    = hashlib.md5(buf).hexdigest()
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
            try:
                self.stdout, self.stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                self.stdout, self.stderr = proc.communicate()
            self.stdout = self.stdout.decode(errors='ignore').strip()
            self.stderr = self.stderr.decode(errors='ignore').strip()
            self.pid = proc.pid
            self.returncode = proc.returncode

    def __init__(self):
        self._dt_begin = haklib.dt.utcnow() - datetime.timedelta(seconds=1)
        self.count_spec_failed = 0
        self.count_exec_failed = 0
        self.count_failed = 0
        self.count_ignored = 0
        self.count_success = 0
        self._testcases = []
        self.ignored_testcases = []
        self.failed_testcases = []

    def _exec_failed(self):
        self.count_spec_failed += 1
        self.count_failed += 1

    def _spec_failed(self):
        self.count_spec_failed += 1
        self.count_failed += 1

    def _ignored(self):
        self.count_ignored += 1

    def _success(self):
        self.count_success += 1

    def add_test(self, path):
        print("running %s" % path)
        argv = [path]
        if '/sudo-' in path:
            argv = ['sudo', '-n'] + argv
        ex = TestRunner.Run(argv, timeout=10)
        specs = ex.stdout.strip().splitlines()
        specs = [line for line in specs if line.startswith('spec:')]
        if len(specs) > 0:
            self._testcases.append((path, ex, specs))
        else:
            print("no specs - ignoring %s" % path)
            self._ignored()
            self.ignored_testcases.append(path)

    def evaluate(self, debug=False):
        logfile = '/var/log/xnumon.log'
        self._dt_end = haklib.dt.utcnow() + datetime.timedelta(seconds=1)
        print("waiting for logs to be written")
        time.sleep(1)
        print("reading logs from %s..." % logfile)
        logs = Logs(logfile, begin=self._dt_begin, end=self._dt_end)
        print("%i log records within relevant timeframe" % len(logs))
        print()
        self.failed_testcases = []
        for path, ex, specs in self._testcases:
            print(brightwhite("testing %s" % path))
            specs = Specs(specs)
            if specs.check(ex, logs):
                self._success()
                keyword = green("success")
            else:
                self._spec_failed()
                keyword = red("failed")
                self.failed_testcases.append(path)
                print("re-checking testcase in verbose mode:")
                specs.check(ex, logs, verbose=True, debug=debug)
            print("%s %s" % (keyword, path))
            print()

def main(paths, debug=False):
    runner = TestRunner()
    for path in paths:
        if path == '-':
            for line in sys.stdin:
                runner.add_test(line)
        else:
            runner.add_test(path)
    runner.evaluate(debug=debug)
    if runner.count_ignored > 0:
        print("%i testcases ignored:" % runner.count_ignored)
        for tc in runner.ignored_testcases:
            print("%s" % tc)
        print()
    if runner.count_failed > 0:
        print("%i testcases failed:" % runner.count_failed)
        for tc in runner.failed_testcases:
            print("%s" % tc)
        print()
    print("%i success %i failed %i ignored" % (
        runner.count_success, runner.count_failed, runner.count_ignored))
    if runner.count_failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    args = sys.argv[1:]
    try:
        args.remove('-v')
        debug=True
    except:
        debug=False
    if len(args) == 0:
        sys.exit(2)
    main(args, debug=debug)

