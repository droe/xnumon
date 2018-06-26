### xnumon develop

-   Fix ancestors default if not set from 0 back to unlimited as documented.
-   Event schema version increased to 3.  Changes affect eventcode 1.
    Eventcode 1 removed evtloop.needargv, evtloop.needcwd.
    Eventcode 1 added evtloop.radar38845784, evtloop.radar38845422_fatal,
    evtloop.radar39267328_fatal, evtloop.radar39623812_fatal.
-   Minor bugfixes and improvements.


### xnumon 0.1.2 2018-06-24

-   Fix handling of `ptrace` and `task_for_pid` audit events for pid 0 or -1.
-   Fix default hash if unspecified to be sha256 as documented in the default
    config.
-   Add `events` config option to configure the desired eventcodes (issue #1).
-   Add `stats_interval` config option to control how often xnumon-stats[1]
    events are generated.
-   Add `debug` config option to control whether debug messages are logged to
    stderr.
-   Add `reload|restart` target to `xnumonctl`, rename `logstats` to `event1`.
-   Event schema version increased to 2.  Changes affect eventcodes 0 and 1.
    Eventcode 0 added config.events, config.stats_interval, config.debug.
    Eventcode 1 removed evtloop.pathbugs, procmon.cwdmiss, procmon.eimiss;
    added evtloop.radar38845422, evtloop.radar39267328, evtloop.radar39623812,
    evtloop.needpath, evtloop.needargv, evtloop.needcwd, procmon.miss.bypid,
    procmon.miss.forksubj, procmon.miss.execsubj, procmon.miss.execinterp,
    procmon.miss.chdirsubj, procmon.miss.getcwd.
-   Minor bugfixes and improvements.


### xnumon 0.1.1 2018-06-17

-   Fix code signature extraction by using the strictest possible form of
    code signature verification.  Addresses fat binaries containing a
    combination of good and bad Mach-O binaries mistakenly being treated as
    having a good signature, as published by Josh Pitts of okta.
-   Fix installer package scripts for installing on external disks.
-   Harden permissions on default configuration file and directory.


### xnumon 0.1.0 2018-06-15

Initial release at [AREA41](//a41con.ch) 2018.
