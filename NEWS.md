### xnumon develop

-   Fix code signature extraction by using the strictest possible form of
    code signature verification.  Addresses fat binaries containing a
    combination of good and bad Mach-O binaries mistakenly being treated as
    having a good signature.
-   Fix installer package scripts for installing on external disks.
-   Harden permissions on default configuration file and directory.

### xnumon 0.1.0 2018-06-15

Initial release at [AREA41](//a41con.ch) 2018.
