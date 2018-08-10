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

# Plenty of refactoring opportunities here, feel free to submit pull requests.

import datetime
import hashlib
import json
import os
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


def tc(path):
    if path.startswith('testcases/'):
        return path[10:]
    return path

def tclog(path):
    path = "trace." + os.path.basename(path)
    if path.endswith(".stest"):
        return path[:-6]
    if path.endswith(".test"):
        return path[:-5]
    return path


class Logs:
    """
    Encapsulates log access and spec evaluation against a set of logs.
    """
    def __init__(self, logfilepath, begin=None, end=None):
        self._all_records = []
        self._records_by_eventcode = []
        n = 0
        with open(logfilepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line == '':
                    continue
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
                obj['_raw'] = line
                obj['_n'] = n
                self._all_records.append(obj)
                self._records_by_eventcode[ec].append(obj)
                n += 1

    def __len__(self):
        count = 0
        for l in self._records_by_eventcode:
            count += len(l)
        return count

    def dump(self, path):
        with open(path, 'w') as f:
            for record in self._all_records:
                f.write(record['_raw'])
                f.write('\n')

    def _render(self, value):
        if isinstance(value, int):
            return "%i" % value
        elif isinstance(value, (list, tuple)):
            return ','.join(value)
        return value

    def _value_for_key(self, record, key):
        node = record
        for subkey in key.split('.'):
            if subkey not in node:
                return None
            node = node[subkey]
        return node

    def _test_conditions(self, record, conds, ex, verbose=False):
        trace = []
        for key, value in conds:
            have_value = self._value_for_key(record, key)
            if not have_value:
                trace.append("%i: %s missing" % (record['_n'], key))
                return False, trace
            have_value = self._render(have_value)
            if value == '*':
                if key.endswith('.sha256'):
                    value = ex.sha256
                elif key.endswith('.sha1'):
                    value = ex.sha1
                elif key.endswith('.md5'):
                    value = ex.md5
            if have_value != value:
                trace.append("%i: %s want %s != have %s" % (record['_n'], key,
                                                            value, have_value))
                return False, trace
            else:
                trace.append("%i: %s want %s == %s" % (record['_n'], key,
                                                       value, have_value))
        return True, trace

    def find(self, eventcode, conds, ex):
        trace = []
        if len(self._records_by_eventcode) < eventcode + 1:
            trace.append("no log records with eventcode=%i" % eventcode)
            return [], trace
        matching_records = []
        for record in self._records_by_eventcode[eventcode]:
            verdict, condtrace = self._test_conditions(record, conds, ex)
            trace.extend(condtrace)
            if verdict:
                trace.append("%i: matched" % record['_n'])
                matching_records.append(record)
        return matching_records, trace


class Specs:
    """
    Represents a list of Spec instances.
    """
    class Spec:
        """
        Represents a single test spec as parsed from the stdout of the executed
        test case executables.
        """
        _EVENTMAP = {
            'xnumon-ops':     0,
            'xnumon-stats':   1,
            'image-exec':     2,
            'process-access': 3,
            'launchd-add':    4,
            'socket-listen':  5,
            'socket-accept':  6,
            'socket-connect': 7,
        }
        def __init__(self, spec):
            parts = spec.strip().split(' ')
            header = parts[0].split(':')
            self._wanted = 1
            self.radar = None
            if len(header) > 2:
                flags = header[-2].split(',')
                if 'absent' in flags:
                    self._wanted = 0
                elif '2' in flags:
                    self._wanted = 2
                for flag in flags:
                    if flag.startswith('radar'):
                        self.radar = flag
                        break
            self._spectype = header[-1]
            if self._spectype != 'testcase':
                self._eventcode = self._EVENTMAP[self._spectype]
            self._conditions = [part.split('=') for part in parts[1:]]
            self._spec = spec
            self._trace = []

        def check(self, ex, logs):
            self._trace.append("%s" % self._spec)
            if self._spectype == 'testcase':
                for key, value in self._conditions:
                    if key == 'returncode':
                        if ex.returncode != int(value):
                            msg = "expected returncode %s but have %i:" % (
                                                       value, ex.returncode)
                            msg += (ex.stderr or "(no stderr)")
                            self._trace.append(msg)
                            print(msg)
                            return False
                    else:
                        msg = yellow("error") + ": unknown condition %s=%s" % (
                                                                    key, value)
                        self._trace.append(msg)
                        print(msg)
                        return False
                return True
            results, trace = logs.find(self._eventcode, self._conditions, ex)
            self._trace.extend(trace)
            self._trace.append("%i matching records" % len(results))
            verdict = len(results) == self._wanted
            if not verdict and self.radar:
                self._trace.append("radared")
                return None
            if verdict:
                self._trace.append("success")
            else:
                self._trace.append("failed")
            return verdict

        def trace(self):
            return '\n'.join(self._trace + [''])

        def __str__(self):
            return self._spec

    def __init__(self, specs):
        self._specs = [self.Spec(spec) for spec in specs]

    def check(self, ex, logs):
        result = True
        radared_radars = []
        success_radars = []
        for spec in self._specs:
            verdict = spec.check(ex, logs)
            if not verdict:
                print("%s  %s" % (red("failed"), spec))
                if verdict == None:
                    if result:
                        result = None
                    radared_radars.append(spec.radar)
                else:
                    result = False
            else:
                print("%s %s" % (green("success"), spec))
                if spec.radar:
                    success_radars.append(spec.radar)
        return result, radared_radars, success_radars

    def dump(self, tclogfile):
        with open(tclogfile, 'w') as f:
            for spec in self._specs:
                f.write(spec.trace())
                f.write('\n')


class TestSuite:
    """
    This class is responsible for managing the complete set of tests.
    """
    class Run:
        """
        Represents a single test case execution and encapsulates all the
        relevant meta-data from the execution, such as hashes of the executable
        before execution, stdout/stderr, pid and returncode.
        """
        def __init__(self, argv, timeout=None):
            self.path = argv[0]
            if self.path == 'sudo':
                self.path = argv[2]
            if '/' in self.path:
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
        self._testcases = []
        self.success_testcases = []
        self.failed_testcases = []
        self.ignored_testcases = []
        self.radared_testcases = []
        self.radared_radars = set()
        self.success_radars = set()
        self._ipv6 = self._test_ipv6()
        if self._ipv6:
            print("IPv6 connectivity working")
        else:
            print(yellow("IPv6 connectivity broken"))

    def _test_ipv6(self):
        argv = ['nc', '-z', '-6', '2a01:7c8:aab0:1fb::1', '80']
        ex = TestSuite.Run(argv, timeout=10)
        return ex.returncode == 0

    def _success(self, path):
        self.success_testcases.append(path)

    def _failed(self, path):
        self.failed_testcases.append(path)

    def _radared(self, path):
        self.radared_testcases.append(path)

    def _ignored(self, path):
        self.ignored_testcases.append(path)

    def add_test(self, path):
        """
        Add a single test case to the test suite.
        Results in the test case being executed and the spec collected for
        later evaluation.
        """
        if not self._ipv6 and ('tcp6' in path or
                               'udp6' in path or
                               'sctp6' in path or
                               'raw6' in path):
            print("no ipv6 - ignoring %s" % tc(path))
            self._ignored(path)
            return
        print("running %s" % tc(path))
        argv = [path]
        if '.sudo.' in path:
            argv = ['sudo', '-n'] + argv
        ex = TestSuite.Run(argv, timeout=10)
        specs = ex.stdout.strip().splitlines()
        specs = [line for line in specs if line.startswith('spec:')]
        if len(specs) > 0:
            self._testcases.append((path, ex, specs))
        else:
            print("no specs - ignoring %s" % tc(path))
            self._ignored(path)

    def evaluate(self):
        """
        Evaluate the added tests and their specs against the logs from the
        relevant time window.
        """
        logfile = '/var/log/xnumon.log'
        self._dt_end = haklib.dt.utcnow() + datetime.timedelta(seconds=1)
        print("waiting for logs to be written")
        time.sleep(1)
        print("reading logs from %s..." % logfile)
        logs = Logs(logfile, begin=self._dt_begin, end=self._dt_end)
        print("%i log records within relevant timeframe" % len(logs))
        print()
        outfiles = []
        self.failed_testcases = []
        for path, ex, specs in self._testcases:
            print(brightwhite("testing %s" % tc(path)))
            specs = Specs(specs)
            verdict, radared_radars, success_radars = specs.check(ex, logs)
            self.radared_radars = self.radared_radars.union(set(radared_radars))
            self.success_radars = self.success_radars.union(set(success_radars))
            if verdict:
                self._success(path)
                keyword = green("success")
            elif verdict == None:
                self._radared(path)
                keyword = yellow("radared")
            else:
                self._failed(path)
                keyword = red("failed")
                tclogfile = tclog(path)
                specs.dump(tclogfile)
                outfiles.append(tclogfile)
            print("%s %s" % (keyword, tc(path)))
            print()
        if len(self.failed_testcases) > 0:
            logfile = 'logs.json'
            logs.dump(logfile)
            outfiles.append(logfile)
        return outfiles


def main(paths):
    """
    Add the requested test cases, evaluate the specs and print the results.
    """
    suite = TestSuite()
    for path in paths:
        if path == '-':
            for line in sys.stdin:
                suite.add_test(line)
        else:
            suite.add_test(path)
    outfiles = suite.evaluate()
    if len(suite.success_testcases) > 0:
        print("%i testcases succeeded" % len(suite.success_testcases))
        #for path in suite.success_testcases:
        #    print("%s" % tc(path))
        print()
    if len(suite.success_radars) > 0:
        print("%i radars absent:" % len(suite.success_radars))
        for radar in sorted(list(suite.success_radars)):
            print("%s" % radar)
        print()
    if len(suite.radared_testcases) > 0:
        print("%i testcases radared:" % len(suite.radared_testcases))
        for path in suite.radared_testcases:
            print("%s" % tc(path))
        print()
    if len(suite.radared_radars) > 0:
        print("%i radars present:" % len(suite.radared_radars))
        for radar in sorted(list(suite.radared_radars)):
            print("%s" % radar)
        print()
    if len(suite.ignored_testcases) > 0:
        print("%i testcases ignored:" % len(suite.ignored_testcases))
        for path in suite.ignored_testcases:
            print("%s" % tc(path))
        print()
    if len(suite.failed_testcases) > 0:
        print("%i testcases failed:" % len(suite.failed_testcases))
        for path in suite.failed_testcases:
            print("%s" % tc(path))
        print()
    if len(outfiles) > 0:
        print("written: " + ' '.join(outfiles))
    print("%i failed %i ignored %i radared %i success" % (
        len(suite.failed_testcases),
        len(suite.ignored_testcases),
        len(suite.radared_testcases),
        len(suite.success_testcases)))
    if len(suite.failed_testcases) > 0:
        return 1
    return 0


if __name__ == '__main__':
    """
    Parse command line and execute main.
    """
    paths = sys.argv[1:]
    if len(paths) == 0:
        sys.exit(2)
    sys.exit(main(paths))

