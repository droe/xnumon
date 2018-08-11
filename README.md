# xnumon - monitor macOS for malicious activity
https://www.roe.ch/xnumon

[//]: # (__BUILD_VERSION__)


## Overview

xnumon is a monitoring agent that produces system activity logs intended to be
suitable for monitoring potentially large fleets of macOS systems for malware
and intrusions.  It aims at providing similar capabilities on macOS that sysmon
provides on Windows.

Currently implemented are the following
[log events](https://github.com/droe/xnumon/wiki/Event-Schemata):

-   **xnumon-ops[0]** and **xnumon-stats[1]**: for in-band monitoring of agent
    status and activity metrics.&nbsp;<sup>&ast;</sup>
-   **image-exec[2]**: a process has replaced its executable image as a result
    of calling execve(2) or posix_spawn(2).&nbsp;<sup>&ast;</sup>
-   **process-access[3]**: a process has accessed and possibly manipulated
    another process using either task_for_pid or
    ptrace(2).&nbsp;<sup>&Dagger;</sup>
-   **launchd-add[4]**: a process has added or modified a launch daemon or
    launch agent plist.&nbps;<sup>&sect;</sup>
-   **socket-listen[5]**: a process has started listening on a
    socket.&nbsp;<sup>&ast;</sup>
-   **socket-accept[6]**: a process has accepted an incoming
    connection.&nbsp;<sup>&sect;</sup>
-   **socket-connect[7]**: a process has initiated an outgoing
    connection.&nbsp;<sup>&dagger;</sup>

<sup>&ast;</sup>    _stable_  
<sup>&dagger;</sup> _stable, but limited in scope due to Apple bugs in audit(4)
not fixed in any supported version of macOS_  
<sup>&Dagger;</sup> _stable, but limited in scope due to Apple bugs in audit(4)
fixed in some but not all supported versions of macOS_  
<sup>&sect;</sup>   _experimental_

xnumon provides context information such as executable image hashes, code
signature meta-data, script shebang handling, and the history of previous
executable images that led to the current process state.  It does so by
tracking fork and other syscalls instead of relying only on the ppid, which
can change over the lifetime of a process.

xnumon is configurable.  It supports different log formats and hash algorithms.
In order to reduce log volume close to the source, xnumon implements a number
of suppression mechanisms and allows tuning the level of information per event.
The log subsystem was designed to be easy to extend with custom log drivers.


## Requirements

A supported version of OS X or macOS, currently:

-   OS X 10.11 El Capitan
-   macOS 10.12 Sierra
-   macOS 10.13 High Sierra
-   macOS 10.14 Mojave

Releases of xnumon are considered safe to deploy in production environments.


## Documentation

See the [xnumon wiki](https://github.com/droe/xnumon/wiki) for further
documentation.  While the wiki is still work in progress, some useful starting
points:

-   `cat /var/log/xnumon.log | jq 'select(.eventcode==0)'`
-   `xnumonctl`
-   `xnumon -h`
-   `dmesg | grep xnumon`


## Installing

The installer package published on the
[xnumon website](https://www.roe.ch/xnumon)
will install the daemon, the control utility and a default configuration which
by default will log to `/var/log/xnumon.log` in JSON Lines format.  It will
also install a matching newsyslog configuration and the optional kernel
extension.  The kernel extension is currently unsigned and as such will not be
usable in production environments unless you control a kext signing certificate
(see «Kernel Extension» below).

The extensively commented default configuration is installed to
`/Library/Application Support/ch.roe.xnumon/configuration.plist-default`.
While the defaults are as sensible as possible, you will most likely want to
maintain a custom configuration at
`/Library/Application Support/ch.roe.xnumon/configuration.plist` to be used
in favour of the default configuration, especially for enterprise deployments.

In addition to installing xnumon, you will want to make sure that auditd does
not clobber the global kernel audit policy.  Make sure the `argv` policy flag
is enabled in `/etc/security/audit_control`, which is the default.  If you are
using `envlevel` `dyld` or `full`, then `arge` is needed in addition to `argv`.

In order to make the logs useful and to get them out of reach of malware and
attackers, it is recommended to continuously forward logs to central log
collection infrastructure.  A minimal sample Splunk configuration for ingesting
xnumon logs can be found in `extra/splunk`.


## Kernel Extension

The xnumon kext is optional and provides reliable acquisition of image hashes
and code signing information even for short-living images using the Kauth KPI.
The kernel extension is currently unsigned and therefore cannot be deployed
unless you own a kernel signing certificate.  A kernel signing certificate for
xnumon has been requested from Apple, but has not been approved yet.

To load the unsigned kext for testing and development, you need to disable
System Integrity Protection (SIP) for kexts.  Reboot to repair mode by pressing
<kbd>cmd⌘</kbd>+<kbd>r</kbd> during boot and from within the repair console,
run `csrutil enable --without kext`.  This will also turn off the kext user
consent requirement of High Sierra.

In addition to a code signature, the kext needs more field testing, especially
compatibility tests with more security solutions, before recommending
large-scale deployments.


## Uninstalling

~~~
xnumonctl uninstall
~~~

This will remove all traces of this package from your system, including logs
at the default location `/var/log/xnumon.log*`, but not including the config
at `/Library/Application Support/ch.roe.xnumon/configuration.plist` unless it
is the same as the default config.


## Build Dependencies

Building an unsigned userland binary and kernel extension requires Xcode
command line tools.  The userland binary requires only the CoreFoundation and
Security frameworks and libbsm; there are no third-party dependencies.

Building a signed userland binary requires an Application Developer ID
certificate from Apple.

Building a signed kernel extension requires a Kext Developer ID certificate
from Apple.

Building signed binary packages requires `pandoc` and an Installer Developer ID
certificate from Apple.


## Debugging

Use `make test` while xnumon is logging to `/var/log/xnumon.log` to execute a
set of automated test cases, exercising different APIs and automatically
checking the log file for the expected events.  Submitting a pull request with
a failing testcase is the best way to report bugs.

Use the metrics in eventcode 1 events to monitor xnumon internals, possibly
reducing the interval it gets generated in the configuration.

Enable `debug` in the configuration and run `xnumonctl logstderr` to change
the launchd plist for xnumon to send stderr to `/var/log/xnumon.stderr`.
This will allow you to get context information for fatal events that would
otherwise only be visible in one of the eventcode 1 metrics.

For short-term debugging during development you can also just unload xnumon
using `xnumonctl unload` and run xnumon with `-o debug=true` on the command
line.

Pass `DEBUG=1` to make in order to build a debug version of xnumon that
includes symbols, assertions and additional debugging code.  See make file
for details.


## Copyright and License

Copyright (c) 2017-2018, [Daniel Roethlisberger](//daniel.roe.ch/).  
All rights reserved.  
Licensed under the Open Software License version 3.0.  
Contains components licensed under BSD and MIT licenses.

See `LICENSE`, `LICENSE.contrib` and `LICENSE.third` as well as the respective
source file headers for details.


## Sponsoring

If you are interested in supporting the development and maintenance of xnumon,
[contact me](mailto:daniel@roe.ch).
