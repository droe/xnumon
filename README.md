# xnumon - monitor macOS for malicious activity
https://www.roe.ch/xnumon

[//]: # (__BUILD_VERSION__)


## Overview

xnumon is a monitoring agent that produces system activity logs intended to be
suitable for monitoring potentially large fleets of macOS systems for malware
and intrusions.  It aims at providing similar capabilities on macOS that sysmon
provides on Windows.

Currently implemented are the following log events:

-   **xnumon-ops[0]** and **xnumon-stats[1]** for in-band monitoring of agent
    status and activity metrics.
-   **exec-image[2]**: a process has replaced its executable image as a result
    of calling one of the execve(2) or posix_spawn(2) family syscalls.
-   **process-access[3]**: a process has accessed and possibly manipulated
    another process using either the task_for_pid or ptrace(2) syscalls.
-   **launchd-add[4]**: a process has added or modified a launch daemon or
    launch agent plist.

xnumon provides context information such as executable image hashes, code
signing meta-data, script shebang handling, and the history of previous
executable images that led to the current process state.  It does so by
tracking fork and other syscalls instead of relying only on the ppid, which
can change over the lifetime of a process.


## Requirements

A supported version of OS X or macOS, currently:

-   OS X 10.11 El Capitan
-   macOS 10.12 Sierra
-   macOS 10.13 High Sierra


## Documentation

More complete documentation has yet to be written.  Some useful commands:

-   `cat /var/log/xnumon.log | jq 'select(.eventcode==0)'`
-   `xnumonctl`
-   `xnumon -h`
-   `dmesg | grep xnumon`


## Installing

The installer package will install the daemon, the control utility and a
default configuration which by default will log to /var/log/xnumon.log in JSON
Lines format.  It will also install a matching newsyslog configuration and the
optional kernel extension.  The kernel extension is currently unsigned and as
such will not be usable in production environments unless you control a kext
signing certificate (see «Kernel Extension» below).

The extensively commented default configuration is installed to
`/Library/Application Support/ch.roe.xnumon/configuration.plist-default`.
While the defaults are as sensible as possible, you will most likely want to
maintain a custom configuration at
`/Library/Application Support/ch.roe.xnumon/configuration.plist` to be used
in favour of the default configuration.

In addition to installing xnumon, you will want to make sure that auditd does
not clobber the global kernel audit policy.  Make sure the `argv` policy flag
is enabled in `/etc/security/audit_control`, which is the default.  Right now,
xnumon does not process the additional information provided by the `arge` flag,
but most likely will start doing so in a future release.

In order to make the logs useful and to get them out of reach of malware and
attackers, it is recommended to continuously forward logs to central log
collection infrastructure.  A sample Splunk configuration for ingesting xnumon
logs can be found in `extra/splunk`.


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
certificate.

Building a signed kernel extension requires an Kext Developer ID certificate.

Building signed binary packages requires `pandoc` and an Installer Developer ID
certificate.


## Copyright and License

Copyright (c) 2017-2018, [Daniel Roethlisberger](//daniel.roe.ch/).  
All rights reserved.  
Licensed under the Open Software License version 3.0.  
Contains components licensed under BSD and MIT licenses.

See `LICENSE`, `LICENSE.contrib` and `LICENSE.third` as well as the respective
source file headers for details.
