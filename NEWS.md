### xnumon develop

-   Fix automatic configuration reloading to pick up changes to the config file
    during the first five minutes and during initialization.

---

### xnumon 0.1.4 2018-07-15

-   Add `json-seq` log format, as defined in RFC 7464:  JSON objects are each
    prefixed by an ASCII Record Separator and terminated by an ASCII Line Feed
    character (issue #13).
-   Mark all image execs as well as subject and object processes that were
    reconstructed by pid instead of from audit events with a `reconstructed`
    field.
-   Generate an image exec event for processes that were missed during exec for
    some reason and are reconstructed by pid later on for context.
-   Make configurable whether processes already running at xnumon agent start
    should generate an image exec event (issue #8).
-   Fix text rendering of `signature` field on images.
-   Use travis-ci.com for continuous integration on supported macOS versions
    (issue #24).

Configuration changes:

-   Add `suppress_image_exec_at_start`.

Event schema changes:

-   Event schema version increased to 4.  Changes affect all eventcodes.
-   Eventcode 2 added `reconstructed`.
-   Eventcode 4 added `object.reconstructed`.
-   All eventcodes added `subject.reconstructed`.

---

### xnumon 0.1.3 2018-07-07

-   Fix ancestors default if not set from 0 back to unlimited as documented and
    omit ancestors array entirely if ancestors is 0.
-   Suppressions by path now also match the script path, not only the image or
    interpreter path.
-   Add ability to suppress child image exec events by ancestor ident or path
    in order to be able to suppress noisy things like MacPorts builds
    (issue #22).
-   Streamlined signer information from code signatures now includes
    developer ID and team ID instead of the full certificate chain, which
    results in lower heap usage and lower log volume for essentially the same
    information (issue #20).
-   Extract CDHash from code signatures (issue #21).
-   Add ability to omit hashes for Apple-signed binaries, enabled by default
    (issue #2).
-   Verify that signatures on Apple binaries are anchored at the Apple root.

Configuration changes:

-   Rename `suppress_process_access_by_ident` and
    `suppress_process_access_by_path` to
    `suppress_process_access_by_subject_ident` and
    `suppress_process_access_by_subject_path`.
-   Add `suppress_image_exec_by_ancestor_ident` and
    `suppress_image_exec_by_ancestor_path`.
-   Add `omit_apple_hashes`.

Event schema changes:

-   Event schema version increased to 3.  Changes affect all eventcodes.
-   Eventcode 1 replaced `evtloop.needargv`, `evtloop.needcwd` and
    `evtloop.needpath` with `evtloop.radar38845422_fatal`,
    `evtloop.radar39267328_fatal` and `evtloop.radar39623812_fatal`.
-   Eventcode 1 added `evtloop.missingtoken` and `evtloop.radar38845784`.
-   Eventcode 2 replaced `image.codesign.result`, `image.codesign.cert`,
    `image.codesign.chain` with `image.signature`, `image.teamid` and
    `image.devid`.
-   Eventcode 2 added `image.cdhash`.
-   All eventcodes added `subject.image.teamid` and
    `subject.ancestors[].teamid`.

---

### xnumon 0.1.2 2018-06-24

-   Fix handling of `ptrace` and `task_for_pid` audit events for pid 0 or -1.
-   Fix default hash if unspecified to be sha256 as documented in the default
    config.

Configuration changes:

-   Add `events` config option to configure the desired eventcodes (issue #1).
-   Add `stats_interval` config option to control how often xnumon-stats[1]
    events are generated.
-   Add `debug` config option to control whether debug messages are logged to
    stderr.
-   Add `reload|restart` target to `xnumonctl`, rename `logstats` to `event1`.

Event schema changes:

-   Event schema version increased to 2.  Changes affect eventcodes 0 and 1.
    Eventcode 0 added config.events, config.stats_interval, config.debug.
    Eventcode 1 removed evtloop.pathbugs, procmon.cwdmiss, procmon.eimiss;
    added evtloop.radar38845422, evtloop.radar39267328, evtloop.radar39623812,
    evtloop.needpath, evtloop.needargv, evtloop.needcwd, procmon.miss.bypid,
    procmon.miss.forksubj, procmon.miss.execsubj, procmon.miss.execinterp,
    procmon.miss.chdirsubj, procmon.miss.getcwd.

---

### xnumon 0.1.1 2018-06-17

-   Fix code signature extraction by using the strictest possible form of
    code signature verification.  Addresses fat binaries containing a
    combination of good and bad Mach-O binaries mistakenly being treated as
    having a good signature, as published by Josh Pitts of okta.
-   Fix installer package scripts for installing on external disks.
-   Harden permissions on default configuration file and directory.

---

### xnumon 0.1.0 2018-06-15

Initial release at [AREA41](//a41con.ch) 2018.
