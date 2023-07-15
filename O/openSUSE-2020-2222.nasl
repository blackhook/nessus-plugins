#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2222.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(144120);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/16");

  script_cve_id("CVE-2019-13207", "CVE-2020-28935");

  script_name(english:"openSUSE Security Update : nsd (openSUSE-2020-2222)");
  script_summary(english:"Check for the openSUSE-2020-2222 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for nsd fixes the following issues :

nsd was updated to the new upstream release 4.3.4

FEATURES :

  - Merge PR #141: ZONEMD RR type.

BUG FIXES :

  - Fix that symlink does not interfere with chown of
    pidfile (boo#1179191, CVE-2020-28935)

  - Fix #128: Fix that the invalid port number is logged for
    sendmmsg failed: Invalid argument.

  - Fix #133: fix 0-init of local ( stack ) buffer.

  - Fix #134: IPV4_MINIMAL_RESPONSE_SIZE vs
    EDNS_MAX_MESSAGE_LEN.

  - Fix to add missing closest encloser NSEC3 for wildcard
    nodata type DS answer.

  - Fix #138: NSD returns non-EDNS answer when QUESTION is
    empty.

  - Fix #142: NODATA answers missin SOA in authority section
    after CNAME chain.

New upstream release 4.3.3 :

FEATURES :

  - Follow DNS flag day 2020 advice and set default EDNS
    message size to 1232.

  - Merged PR #113 with fixes. Instead of listing an
    IP-address to listen on, an interface name can be
    specified in nsd.conf, with ip-address: eth0. The
    IP-addresses for that interface are then used.

  - New upstream release 4.3.2

FEATURES :

  - Fix #96: log-only-syslog: yes sets to only use syslog,
    fixes that the default configuration and systemd results
    in duplicate log messages.

  - Fix #107: nsd -v shows configure line, openssl version
    and libevent version.

  - Fix #103 with #110: min-expire-time option. To provide a
    lower bound for expire period. Expressed in number of
    seconds or refresh+retry+1.

BUG FIXES :

  - Fix to omit the listen-on lines from log at startup,
    unless verbose.

  - Fix #97: EDNS unknown version: query not in response.

  - Fix #99: Fix copying of socket properties with reuseport
    enabled.

  - Document default value for tcp-timeout.

  - Merge PR#102 from and0x000: add missing default in
    documentation for drop-updates.

  - Fix unlink of pidfile warning if not possible due to
    permissions, nsd can display the message at high
    verbosity levels.

  - Removed contrib/nsd.service, example is too complicated
    and not useful.

  - Merge #108 from Nomis: Make the max-retry-time
    description clearer.

  - Retry when udp send buffer is full to wait until buffer
    space is available.

  - Remove errno reset behaviour from sendmmsg and recvmmsg
    replacement functions.

  - Fix unit test for different nsd-control-setup -h exit
    code.

  - Merge #112 from jaredmauch: log old and new serials when
    NSD rejects an IXFR due to an old serial number.

  - Fix #106: Adhere better to xfrd bounds. Refresh and
    retry times.

  - Fix #105: Clearing hash_tree means just emptying the
    tree.

New upstream release 4.3.1

BUG FIXES :

  - Merge PR #91 by gearnode: nsd-control-setup recreate
    certificates. The '-r' option recreates certificates.
    Without it it creates them if they do not exist, and
    does not modify them otherwise.

New upstream release 4.3.0

FEATURES :

  - Fix to use getrandom() for randomness, if available.

  - Fix #56: Drop sparse TSIG signing support in NSD. Sign
    every axfr packet with TSIG, according to the latest
    draft-ietf-dnsop-rfc2845bis-06, Section 5.3.1.

  - Merge pull request #59 from buddyns: add FreeBSD support
    for conf key ip-transparent.

  - Add feature to pin server processes to specific cpus.

  - Add feature to pin IP addresses to selected server
    processes.

  - Set process title to identify individual processes.

  - Merge PR#22: minimise-any: prefer polular and not large
    RRset, from Daisuke Higashi.

  - Add support for SO_BINDTODEVICE on Linux.

  - Add feature to drop queries with opcode UPDATE.

BUG FIXES :

  - Fix whitespace in nsd.conf.sample.in, patch from Paul
    Wouters.

  - use-systemd is ignored in nsd.conf, when NSD is compiled
    with libsystemd it always signals readiness, if
    possible.

  - Note that use-systemd is not necessary and ignored in
    man page.

  - Fix responses for IXFR so that the authority section is
    not echoed in the response.

  - Fix that the retry wait does not exceed one day for zone
    transfers.

  - Update keyring as per https://nlnetlabs.nl/people/

New upstream release 4.2.3 :

  - confine-to-zone configures NSD to not return out-of-zone
    additional information.

  - pidfile '' allows to run NSD without a pidfile

  - adds support for readiness notification with READY_FD

  - fix excessive logging of ixfr failures, it stops the log
    when fallback to axfr is possible. log is enabled at
    high verbosity.

  - The nsd.conf includes are sorted ascending, for include
    statements with a '*' from glob.

  - Fix log address and failure reason with tls handshake
    errors, squelches (the same as unbound) some unless high
    verbosity is used.

  - Number of different UDP handlers has been reduced to
    one. recvmmsg and sendmmsg implementations are now used
    on all platforms.

  - Socket options are now set in designated functions for
    easy reuse.

  - Socket setup has been simplified for easy reuse.

  - Configuration parser is now aware of the context in
    which an option was specified.

  - document that remote-control is a top-level nsd.conf
    attribute.

  - Remove legacy upgrade of nsd users in %post
    (boo#1157331)

New upstream release 4.2.2 :

  - Fix #20: CVE-2019-13207 Stack-based Buffer Overflow in
    the dname_concatenate() function. Reported by Frederic
    Cambus. It causes the zone parser to crash on a
    malformed zone file, with assertions enabled, an
    assertion catches it.

  - Fix #19: Out-of-bounds read caused by improper
    validation of array index. Reported by Frederic Cambus.
    The zone parser fails on type SIG because of mismatched
    definition with RRSIG.

  - PR #23: Fix typo in nsd.conf man-page.

  - Fix that NSD warns for wrong length of the hash in SSHFP
    records.

  - Fix #25: NSD doesn't refresh zones after extended
    downtime, it refreshes the old zones.

  - Set no renegotiation on the SSL context to stop client
    session renegotiation.

  - Fix #29: SSHFP check NULL pointer dereference.

  - Fix #30: SSHFP check failure due to missing domain name.

  - Fix to timeval_add in minievent for remaining second in
    microseconds.

  - PR #31: nsd-control: Add missing stdio header.

  - PR #32: tsig: Fix compilation without HAVE_SSL.

  - Cleanup tls context on xfrd exit.

  - Fix #33: Fix segfault in service of remaining streams on
    exit.

  - Fix error message for out of zone data to have more
    information.

New upstream release 4.2.1 :

  - FEATURES :

  - Added num.tls and num.tls6 stat counters.

  - PR #12: send-buffer-size, receive-buffer-size,
    tcp-reject-overflow options for nsd.conf, from Jeroen
    Koekkoek.

  - Fix #14, tcp connections have 1/10 to be active and have
    to work every second, and then they get time to complete
    during a reload, this is a process that lingers with the
    old version during a version update.

  - BUG FIXES :

  - Fix #13: Stray dot at the end of some log entries,
    removes dot after updated serial number in log entry.

  - Fix TLS cipher selection, the previous was redundant,
    prefers CHACHA20-POLY1305 over AESGCM and was not as
    readable as it could be.

  - Fix #15: crash in SSL library, initialize variables for
    TCP access when TLS is configured.

  - Fix tls handshake event callback function mistake,
    reported by Mykhailo Danylenko.

  - Fix output of nsd-checkconf -h.

New upstream release 4.2.0 :

  - Implement TCP fast open

  - Added DNS over TLS

  - TLS OCSP stapling support with the tls-service-ocsp
    option

  - New option hide-identity can be used in nsd.conf to stop
    NSD from responding with the hostname for probe queries
    that elicit the chaos class response, this is conform
    RFC4892

  - Disable TLS1.0, TLS1.1 and weak ciphers, enable
    CIPHER_SERVER_PREFERENCE

Update to upstream release 4.1.27 :

  - FEATURES :

  - Deny ANY with only one RR in response, by default. Patch
    from Daisuke Higashi. The deny-any statement in nsd.conf
    sets ANY queries over UDP to be further moved to TCP as
    well. Also no additional section processig for type ANY,
    reducing the response size.

  - Fix #4215: on-the-fly change of TSIG keys with patch
    from Igor, adds nsd-control print_tsig, update_tsig,
    add_tsig, assoc_tsig and del_tsig. These changes are
    gone after reload, edit the config file (or a file
    included from it) to make changes that last after
    restart.

  - BUG FIXES :

Update to upstream release 4.1.26 :

  - FEATURES :

  - DNSTAP support for NSD, --enable-dnstap and then config
    in nsd.conf.

  - Support SO_REUSEPORT_LB in FreeBSD 12 with the
    reuseport: yes option in nsd.conf.

  - Added nsd-control changezone. nsd-control changezone
    name pattern allows the change of a zone pattern option
    without downtime for the zone, in one operation.

  - BUG FIXES :

  - Fix #4194: Zone file parser derailed by non-FQDN names
    in RHS of DNSSEC RRs.

  - Fix #4202: nsd-control delzone incorrect exit code on
    error.

  - Fix to not set GLOB_NOSORT so the nsd.conf include:
    files are sorted and in a predictable order.

  - Fix #3433: document that reconfig does not change
    per-zone stats.

Update to upstream release 4.1.25 :

  - FEATURES :

  - nsd-control prints neater errors for file failures.

  - BUG FIXES :

  - Fix that nsec3 precompile deletion happens before the
    RRs of the zone are deleted.

  - Fix printout of accepted remote control connection for
    unix sockets.

  - Fix use_systemd typo/leftover in remote.c.

  - Fix codingstyle in nsd-checkconf.c in patch from Sharp
    Liu.

  - append_trailing_slash has one implementation and is not
    repeated differently.

  - Fix coding style in nsd.c

  - Fix to combine the same error function into one, from
    Xiaobo Liu.

  - Fix initialisation in remote.c.

  - please clang analyzer and fix parse of IPSECKEY with bad
    gateway.

  - Fix nsd-checkconf fail on bad zone name.

  - Annotate exit functions with noreturn.

  - Remove unused if clause during server service startup.

  - Fix #4156: Fix systemd service manager state change
    notification When it is compiled, systemd readiness
    signalling is enabled. The option in nsd.conf is not
    used, it is ignored when read.

Update to upstream release 4.1.24 :

  - Features

  - #4102: control interface via local socket

  - configure --enable-systemd (needs pkg-config and
    libsystemd) can be used to then use-systemd: yes in
    nsd.conf and have readiness signalling with systemd.

  - RFC8162 support, for record type SMIMEA.

  - Bug Fixes

  - Patch to fix openwrt for mac os build darwin detection
    in configure.

  - Fix that first control-interface determines if TLS is
    used. Warn when IP address interfaces are used without
    TLS.

  - #4106: Fix that stats printed from nsd-control are
    recast from unsigned long to unsigned (remote.c).

  - Fix that type CAA (and URI) in the zone file can contain
    dots when not in quotes.

  - #4133: Fix that when IXFR contains a zone with broken
    NSEC3PARAM chain, NSD leniently attempts to find a
    working NSEC3PARAM.

Update to upstream release 4.1.23 :

  - Fix NSD time sensitive TSIG compare vulnerability.

Update to upstream release 4.1.22 :

  - Features :

  - refuse-any sends truncation (+TC) in reply to ANY
    queries over UDP, and allows TCP queries like normal.

  - Use accept4 to speed up answer of TCP queries

  - Bug fixes :

  - Fix nsec3 hash of parent and child co-hosted nsec3
    enabled zones.

  - Fix to use same condition for nsec3 hash allocation and
    free.

  - Changes in version 4.1.21 :

  - Features :

  - --enable-memclean cleans up memory for use with memory
    checkers, eg. valgrind.

  - refuse-any nsd.conf option that refuses queries of type
    ANY.

  - lower memory usage for tcp connections, so tcp-count can
    be higher.

  - Bug fixes :

  - Fix spelling error in xfr-inspect.

  - Fix buffer size warnings from compiler on filename
    lengths."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nlnetlabs.nl/people/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nsd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nsd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nsd-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"nsd-4.1.27-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nsd-debuginfo-4.1.27-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nsd-debugsource-4.1.27-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nsd-4.3.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nsd-debuginfo-4.3.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nsd-debugsource-4.3.4-lp152.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nsd / nsd-debuginfo / nsd-debugsource");
}
