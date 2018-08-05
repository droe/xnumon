#!/usr/bin/env python
# vim: set list et ts=8 sts=4 sw=4 ft=python:

# haklib.dt - missing datetime functionality
# Copyright (C) 2016-2018, Daniel Roethlisberger <daniel@roe.ch>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions, and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Example use:
#
# import haklib.dt
# print(haklib.dt.fromiso8601('2015-03-43 10:01:34 UTC'))

import datetime
import re

class UTC(datetime.tzinfo):
    """
    Simple timezone info class for UTC
    """
    def utcoffset(self, dt):
        return datetime.timedelta(0)
    def tzname(self, dt):
        return "UTC"
    def dst(self, dt):
        return datetime.timedelta(0)

# List of known timezone names
# Note that only timezones with fixed UTC offset are supported.
TZm = {
    'Z':    0,
    'GMT':  0,
    'UTC':  0,
    'CET':  60,
    'CEST': 120,
    # ...
}

def tzs2td(tzs):
    """
    timezone string to datetime.timedelta conversion
    Supports either +/-XX:XX format or timezone name from TZm dict
    """
    if tzs in TZm:
        return datetime.timedelta(minutes=TZm[tzs])
    if tzs[0] == '-':
        sign = -1
    else:
        sign = 1
    h = int(tzs[1:3])
    m = int(tzs[3:5])
    return datetime.timedelta(minutes=(sign*h*60+m))

def fromiso8601(timestamp):
    """
    Parse ISO8601-ish timestamp string with timezone; microseconds are ignored.
    Returns a timezone-aware datetime in the UTC timezone.
    """
    stamp = re.sub(r' *?([+-][0-9]+|[A-Z]+)$', "", timestamp)
    zone = re.sub(r'^.*?([+-][0-9]+|[A-Z]+)$', "\\1", timestamp)
    dt = datetime.datetime(*map(int, re.split('\D', stamp)[0:6]))
    dt = dt - tzs2td(zone)
    return dt.replace(tzinfo=UTC())

def fromepoch(epoch):
    """
    Create TZ aware datetime from UNIX epoch
    """
    return datetime.datetime.fromtimestamp(epoch, UTC())

def utcnow():
    """
    Create TZ aware now
    """
    return datetime.datetime.utcnow().replace(tzinfo=UTC())

def fromdos(dosdt):
    """
    Convert DOS format 32bit timestamp to datetime object.
    Timestamps with illegal values out of the allowed range are ignored and a
    datetime object representing 1980-01-01 00:00:00 is returned instead.
    https://msdn.microsoft.com/en-us/library/9kkf9tah.aspx
    """
    try:
        return datetime.datetime(
                ((dosdt >> 25) & 0x7F) + 1980,
                 (dosdt >> 21) & 0x0F,
                 (dosdt >> 16) & 0x1F,
                 (dosdt >> 11) & 0x1F,
                 (dosdt >>  5) & 0x3F,
                ((dosdt      ) & 0x1F) * 2)
    except ValueError:
        return datetime.datetime(1980, 1, 1, 0, 0, 0)

def ago(dt, now=None):
    """
    Returns the time difference between now and dt in human readable form as a
    string of the form "X time-units ago".
    """
    if now == None:
        now = datetime.datetime.utcnow().replace(tzinfo=UTC())
    secs = int(round((now - dt).total_seconds()))
    if secs == 0:
        return 'now'
    if secs == 1:
        return 'a second ago'
    if secs < 60:
        return '%s seconds ago' % secs
    mins = int(round(secs / 60))
    if mins == 1:
        return 'a minute ago'
    if mins < 60:
        return '%s minutes ago' % mins
    hours = int(round(mins / 60))
    if hours == 1:
        return 'an hour ago'
    if hours < 24:
        return '%s hours ago' % hours
    days = int(round(hours / 24))
    if days == 1:
        return 'a day ago'
    if days < 7:
        return '%s days ago' % days
    weeks = int(round(days / 7))
    if weeks == 1:
        return 'a week ago'
    if weeks < 5:
        return '%s weeks ago' % weeks
    months = int(round(days / 30))
    if months == 1:
        return 'a month ago'
    if months < 12:
        return '%s months ago' % months
    years = int(round(days / 365))
    if years == 1:
        return 'a year ago'
    if years < 10:
        return '%s years ago' % years
    decas = int(round(years / 10))
    if decas == 1:
        return 'a decade ago'
    if decas < 10:
        return '%s decades ago' % decas
    cents = int(round(years / 100))
    if cents == 1:
        return 'a century ago'
    if cents < 10:
        return '%s centuries ago' % cents
    mills = int(round(years / 1000))
    if mills == 1:
        return 'a millenium ago'
    if mills < 10:
        return '%s millenia ago' % mills
    return 'ages ago'

if __name__ == '__main__':
    def _test(dt):
        refstr = '2016-01-06 08:02:04+00:00'
        if not str(dt) == refstr:
            print("%s != %s" % (str(dt), refstr))
        print(dt)
    _test(fromiso8601('2016-01-06 09:02:04 +0100'))
    _test(fromiso8601('2016-01-06 07:02:04 -0100'))
    _test(fromiso8601('2016-01-06 08:02:04 UTC'))
    _test(fromiso8601('2016-01-06T08:02:04Z'))
    _test(fromiso8601('2016-01-06 10:02:04 CEST'))
    _test(fromiso8601('2016-01-06 09:02:04.123 CET'))
    _test(fromepoch(1452067324))
    print(ago(fromiso8601('2016-01-06 09:02:04.123 CET')))
    print(ago(fromiso8601('2015-01-06 09:02:04.123 CET')))
    print(ago(fromiso8601('1253-01-06 09:02:04.123 CET')))
    print(ago(fromiso8601('53-01-06 09:02:04.123 CET')))


