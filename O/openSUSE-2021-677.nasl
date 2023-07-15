#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-677.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149614);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-1000369",
    "CVE-2017-16943",
    "CVE-2017-16944",
    "CVE-2018-6789",
    "CVE-2019-10149",
    "CVE-2019-13917",
    "CVE-2019-15846",
    "CVE-2019-16928",
    "CVE-2020-12783",
    "CVE-2020-28007",
    "CVE-2020-28008",
    "CVE-2020-28009",
    "CVE-2020-28010",
    "CVE-2020-28011",
    "CVE-2020-28012",
    "CVE-2020-28013",
    "CVE-2020-28014",
    "CVE-2020-28015",
    "CVE-2020-28016",
    "CVE-2020-28017",
    "CVE-2020-28018",
    "CVE-2020-28019",
    "CVE-2020-28020",
    "CVE-2020-28021",
    "CVE-2020-28022",
    "CVE-2020-28023",
    "CVE-2020-28024",
    "CVE-2020-28025",
    "CVE-2020-28026"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2019-0413");

  script_name(english:"openSUSE Security Update : exim (openSUSE-2021-677) (Stack Clash)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for exim fixes the following issues :

Exim was updated to exim-4.94.2

security update (boo#1185631)

  - CVE-2020-28007: Link attack in Exim's log directory

  - CVE-2020-28008: Assorted attacks in Exim's spool
    directory

  - CVE-2020-28014: Arbitrary PID file creation

  - CVE-2020-28011: Heap buffer overflow in queue_run()

  - CVE-2020-28010: Heap out-of-bounds write in main()

  - CVE-2020-28013: Heap buffer overflow in
    parse_fix_phrase()

  - CVE-2020-28016: Heap out-of-bounds write in
    parse_fix_phrase()

  - CVE-2020-28015: New-line injection into spool header
    file (local)

  - CVE-2020-28012: Missing close-on-exec flag for
    privileged pipe

  - CVE-2020-28009: Integer overflow in get_stdinput()

  - CVE-2020-28017: Integer overflow in
    receive_add_recipient()

  - CVE-2020-28020: Integer overflow in receive_msg()

  - CVE-2020-28023: Out-of-bounds read in smtp_setup_msg()

  - CVE-2020-28021: New-line injection into spool header
    file (remote)

  - CVE-2020-28022: Heap out-of-bounds read and write in
    extract_option()

  - CVE-2020-28026: Line truncation and injection in
    spool_read_header()

  - CVE-2020-28019: Failure to reset function pointer after
    BDAT error

  - CVE-2020-28024: Heap buffer underflow in smtp_ungetc()

  - CVE-2020-28018: Use-after-free in tls-openssl.c

  - CVE-2020-28025: Heap out-of-bounds read in
    pdkim_finish_bodyhash()

update to exim-4.94.1

  - Fix security issue in BDAT state confusion. Ensure we
    reset known-good where we know we need to not be reading
    BDAT data, as a general case fix, and move the places
    where we switch to BDAT mode until after various
    protocol state checks. Fixes CVE-2020-BDATA reported by
    Qualys.

  - Fix security issue in SMTP verb option parsing
    (CVE-2020-EXOPT)

  - Fix security issue with too many recipients on a message
    (to remove a known security problem if someone does set
    recipients_max to unlimited, or if local additions add
    to the recipient list). Fixes CVE-2020-RCPTL reported by
    Qualys.

  - Fix CVE-2020-28016 (PFPZA): Heap out-of-bounds write in
    parse_fix_phrase()

  - Fix security issue CVE-2020-PFPSN and guard against
    cmdline invoker providing a particularly obnoxious
    sender full name.

  - Fix Linux security issue CVE-2020-SLCWD and guard
    against PATH_MAX better.

  - bring back missing exim_db.8 manual page (fixes
    boo#1173693)

  - bring in changes from current +fixes (lots of taint
    check fixes)

  - Bug 1329: Fix format of Maildir-format filenames to
    match other mail- related applications. Previously an
    'H' was used where available info says that 'M' should
    be, so change to match.

  - Bug 2587: Fix pam expansion condition. Tainted values
    are commonly used as arguments, so an implementation
    trying to copy these into a local buffer was taking a
    taint-enforcement trap. Fix by using dynamically created
    buffers.

  - Bug 2586: Fix listcount expansion operator. Using
    tainted arguments is reasonable, eg. to count headers.
    Fix by using dynamically created buffers rather than a
    local. Do similar fixes for ACL actions 'dcc',
    'log_reject_target', 'malware' and 'spam'; the arguments
    are expanded so could be handling tainted values.

  - Bug 2590: Fix -bi (newaliases). A previous code
    rearrangement had broken the (no-op) support for this
    sendmail command. Restore it to doing nothing, silently,
    and returning good status.

  - update to exim 4.94

  - some transports now refuse to use tainted data in
    constructing their delivery location this WILL BREAK
    configurations which are not updated accordingly. In
    particular: any Transport use of $local_user which has
    been relying upon check_local_user far away in the
    Router to make it safe, should be updated to replace
    $local_user with $local_part_data.

  - Attempting to remove, in router or transport, a header
    name that ends with an asterisk (which is a
    standards-legal name) will now result in all headers
    named starting with the string before the asterisk being
    removed.

  - switch pretrans to use lua (fixes boo#1171877)



  - bring changes from current in +fixes branch
    (patch-exim-fixes-ee83de04d3087efaf808d1f2235a988275c2ee
    94)

  - fixes CVE-2020-12783 (boo#1171490)

  - Regard command-line recipients as tainted.

  - Bug 2489: Fix crash in the 'pam' expansion condition.

  - Use tainted buffers for the transport smtp context.

  - Bug 2493: Harden ARC verify against Outlook, which has
    been seen to mix the ordering of its ARC headers. This
    caused a crash.

  - Bug 2492: Use tainted memory for retry record when
    needed. Previously when a new record was being
    constructed with information from the peer, a trap was
    taken.

  - Bug 2494: Unset the default for dmarc_tld_file.

  - Fix an uninitialised flag in early-pipelining.
    Previously connections could, depending on the platform,
    hang at the STARTTLS response.

  - Bug 2498: Reset a counter used for ARC verify before
    handling another message on a connection. Previously if
    one message had ARC headers and the following one did
    not, a crash could result when adding an
    Authentication-Results: header.

  - Bug 2500: Rewind some of the common-coding in string
    handling between the Exim main code and Exim-related
    utities.

  - Fix the variables set by the gsasl authenticator.

  - Bug 2507: Modules: on handling a dynamic-module
    (lookups) open failure, only retrieve the errormessage
    once.

  - Bug 2501: Fix init call in the heimdal authenticator.
    Previously it adjusted the size of a major service
    buffer; this failed because the buffer was in use at the
    time. Change to a compile-time increase in the buffer
    size, when this authenticator is compiled into exim.

  - update to exim 4.93.0.4 (+fixes release)

  - Avoid costly startup code when not strictly needed. This
    reduces time for some exim process initialisations. It
    does mean that the logging of TLS configuration problems
    is only done for the daemon startup.

  - Early-pipelining support code is now included unless
    disabled in Makefile.

  - DKIM verification defaults no long accept sha1 hashes,
    to conform to RFC 8301. They can still be enabled, using
    the dkim_verify_hashes main option.

  - Support CHUNKING from an smtp transport using a
    transport_filter, when DKIM signing is being done.
    Previously a transport_filter would always disable
    CHUNKING, falling back to traditional DATA.

  - Regard command-line receipients as tainted.

  - Bug 340: Remove the daemon pid file on exit, whe due to
    SIGTERM.

  - Bug 2489: Fix crash in the 'pam' expansion condition. It
    seems that the PAM library frees one of the arguments
    given to it, despite the documentation. Therefore a
    plain malloc must be used.

  - Bug 2491: Use tainted buffers for the transport smtp
    context. Previously on-stack buffers were used,
    resulting in a taint trap when DSN information copied
    from a received message was written into the buffer.

  - Bug 2493: Harden ARC verify against Outlook, whick has
    been seen to mix the ordering of its ARC headers. This
    caused a crash.

  - Bug 2492: Use tainted memory for retry record when
    needed. Previously when a new record was being
    constructed with information from the peer, a trap was
    taken.

  - Bug 2494: Unset the default for dmarc_tld_file.
    Previously a naiive installation would get error
    messages from DMARC verify, when it hit the nonexistent
    file indicated by the default. Distros wanting DMARC
    enabled should both provide the file and set the option.
    Also enforce no DMARC verification for command-line
    sourced messages.

  - Fix an uninitialised flag in early-pipelining.
    Previously connections could, depending on the platform,
    hang at the STARTTLS response.

  - Bug 2498: Reset a counter used for ARC verify before
    handling another message on a connection. Previously if
    one message had ARC headers and the following one did
    not, a crash could result when adding an
    Authentication-Results: header.

  - Bug 2500: Rewind some of the common-coding in string
    handling between the Exim main code and Exim-related
    utities. The introduction of taint tracking also did
    many adjustments to string handling. Since then, eximon
    frequently terminated with an assert failure.

  - When PIPELINING, synch after every hundred or so RCPT
    commands sent and check for 452 responses. This slightly
    helps the inefficieny of doing a large alias-expansion
    into a recipient-limited target. The max_rcpt transport
    option still applies (and at the current default, will
    override the new feature). The check is done for either
    cause of synch, and forces a fast-retry of all 452'd
    recipients using a new MAIL FROM on the same connection.
    The new facility is not tunable at this time.

  - Fix the variables set by the gsasl authenticator.
    Previously a pointer to library live data was being
    used, so the results became garbage. Make copies while
    it is still usable.

  - Logging: when the deliver_time selector ise set, include
    the DT= field on delivery deferred (==) and failed (**)
    lines (if a delivery was attemtped). Previously it was
    only on completion (=>) lines.

  - Authentication: the gsasl driver not provides the $authN
    variables in time for the expansion of the
    server_scram_iter and server_scram_salt options.

spec file cleanup to make update work

  - add docdir to spec

  - update to exim 4.93

  - SUPPORT_DMARC replaces EXPERIMENTAL_DMARC

  - DISABLE_TLS replaces SUPPORT_TLS

  - Bump the version for the local_scan API.

  - smtp transport option hosts_try_fastopen defaults to
    '*'.

  - DNSSec is requested (not required) for all queries.
    (This seemes to ask for trouble if your resolver is a
    systemd-resolved.)

  - Generic router option retry_use_local_part defaults to
    'true' under specific pre-conditions.

  - Introduce a tainting mechanism for values read from
    untrusted sources.

  - Use longer file names for temporary spool files (this
    avoids name conflicts with spool on a shared file
    system).

  - Use dsn_from main config option (was ignored
    previously).

  - update to exim 4.92.3

  - CVE-2019-16928: fix against Heap-based buffer overflow
    in string_vformat, remote code execution seems to be
    possible

  - update to exim 4.92.2

  - CVE-2019-15846: fix against remote attackers executing
    arbitrary code as root via a trailing backslash

  - update to exim 4.92.1

  - CVE-2019-13917: Fixed an issue with $(sort) expansion
    which could allow remote attackers to execute other
    programs with root privileges (boo#1142207)

  - spec file cleanup

  - fix DANE inclusion guard condition

  - re-enable i18n and remove misleading comment

  - EXPERIMENTAL_SPF is now SUPPORT_SPF

  - DANE is now SUPPORT_DANE

  - update to exim 4.92

  - $(l_header:<name>) expansion

  - $(readsocket) now supports TLS

  - 'utf8_downconvert' option (if built with SUPPORT_I18N)

  - 'pipelining' log_selector

  - JSON variants for $(extract ) expansion

  - 'noutf8' debug option

  - TCP Fast Open support on MacOS

  - CVE-2019-10149: Fixed a Remote Command Execution
    (boo#1136587)

  - add workaround patch for compile time error on missing
    printf format annotation (gnu_printf.patch)

  - update to 4.91

  - DEFER rather than ERROR on redis cluster MOVED response.

  - Catch and remove uninitialized value warning in exiqsumm

  - Disallow '/' characters in queue names specified for the
    'queue=' ACL modifier. This matches the restriction on
    the commandline.

  - Fix pgsql lookup for multiple result-tuples with a
    single column. Previously only the last row was
    returned.

  - Bug 2217: Tighten up the parsing of DKIM signature
    headers.

  - Bug 2215: Fix crash associated with dnsdb lookup done
    from DKIM ACL.

  - Fix issue with continued-connections when the DNS shifts
    unreliably.

  - Bug 2214: Fix SMTP responses resulting from non-accept
    result of MIME ACL.

  - The 'support for' informational output now, which built
    with Content Scanning support, has a line for the
    malware scanner interfaces compiled in. Interface can be
    individually included or not at build time.

  - The 'aveserver', 'kavdaemon' and 'mksd' interfaces are
    now not included by the template makefile 'src/EDITME'.
    The 'STREAM' support for an older ClamAV interface
    method is removed.

  - Bug 2223: Fix mysql lookup returns for the no-data case
    (when the number of rows affected is given instead).

  - The runtime Berkeley DB library version is now
    additionally output by 'exim -d -bV'. Previously only
    the compile-time version was shown.

  - Bug 2230: Fix cutthrough routing for nonfirst messages
    in an initiating SMTP connection.

  - Bug 2229: Fix cutthrough routing for nonstandard port
    numbers defined by routers.

  - Bug 2174: A timeout on connect for a callout was also
    erroneously seen as a timeout on read on a GnuTLS
    initiating connection, resulting in the initiating
    connection being dropped.

  - Relax results from ACL control request to enable
    cutthrough, in unsupported situations, from error to
    silently (except under debug) ignoring.

  - Fix Buffer overflow in base64d() (CVE-2018-6789)

  - Fix bug in DKIM verify: a buffer overflow could corrupt
    the malloc metadata, resulting in a crash in free().

  - Fix broken Heimdal GSSAPI authenticator integration.

  - Bug 2113: Fix conversation closedown with the Avast
    malware scanner.

  - Bug 2239: Enforce non-usability of
    control=utf8_downconvert in the mail ACL.

  - Speed up macro lookups during configuration file read,
    by skipping non- macro text after a replacement
    (previously it was only once per line) and by skipping
    builtin macros when searching for an uppercase lead
    character.

  - DANE support moved from Experimental to mainline. The
    Makefile control for the build is renamed.

  - Fix memory leak during multi-message connections using
    STARTTLS.

  - Bug 2236: When a DKIM verification result is overridden
    by ACL, DMARC reported the original. Fix to report (as
    far as possible) the ACL result replacing the original.

  - Fix memory leak during multi-message connections using
    STARTTLS under OpenSSL

  - Bug 2242: Fix exim_dbmbuild to permit directoryless
    filenames.

  - Fix utf8_downconvert propagation through a redirect
    router.

  - Bug 2253: For logging delivery lines under PRDR, append
    the overall DATA response info to the (existing)
    per-recipient response info for the 'C=' log element.

  - Bug 2251: Fix ldap lookups that return a single
    attribute having zero- length value.

  - Support Avast multiline protocol, this allows passing
    flags to newer versions of the scanner.

  - Ensure that variables possibly set during message
    acceptance are marked dead before release of memory in
    the daemon loop.

  - Bug 2250: Fix a longstanding bug in heavily-pipelined
    SMTP input (such as a multi-recipient message from a
    mailinglist manager).

  - The (EXPERIMENTAL_DMARC) variable $dmarc_ar_header is
    withdrawn, being replaced by the $(authresults )
    expansion.

  - Bug 2257: Fix pipe transport to not use a socket-only
    syscall.

  - Set a handler for SIGTERM and call exit(3) if running as
    PID 1. This allows proper process termination in
    container environments.

  - Bug 2258: Fix spool_wireformat in combination with LMTP
    transport. Previously the 'final dot' had a newline
    after it; ensure it is CR,LF.

  - SPF: remove support for the 'spf' ACL condition outcome
    values 'err_temp' and 'err_perm', deprecated since 4.83
    when the RFC-defined words ' temperror' and 'permerror'
    were introduced.

  - Re-introduce enforcement of no cutthrough delivery on
    transports having transport-filters or DKIM-signing.

  - Cutthrough: for a final-dot response timeout (and
    nonunderstood responses) in defer=pass mode supply a 450
    to the initiator. Previously the message would be
    spooled.

  - DANE: add dane_require_tls_ciphers SMTP Transport
    option; if unset, tls_require_ciphers is used as before.

  - Malware Avast: Better match the Avast multiline
    protocol.

  - Fix reinitialisation of DKIM logging variable between
    messages.

  - Bug 2255: Revert the disable of the OpenSSL session
    caching.

  - Add util/renew-opendmarc-tlds.sh script for safe renewal
    of public suffix list.

  - DKIM: accept Ed25519 pubkeys in
    SubjectPublicKeyInfo-wrapped form, since the IETF WG has
    not yet settled on that versus the original 'bare'
    representation.

  - Fix syslog logging for syslog_timestamp=no and
    log_selector +millisec. Previously the millisecond value
    corrupted the output. Fix also for syslog_pid=no and
    log_selector +pid, for which the pid corrupted the
    output.

  - Replace xorg-x11-devel by individual pkgconfig()
    buildrequires. 

  - update to 4.90.1

  - Allow PKG_CONFIG_PATH to be set in Local/Makefile and
    use it correctly during configuration. Wildcards are
    allowed and expanded.

  - Shorten the log line for daemon startup by collapsing
    adjacent sets of identical IP addresses on different
    listening ports. Will also affect 'exiwhat' output.

  - Tighten up the checking in isip4 (et al): dotted-quad
    components larger than 255 are no longer allowed.

  - Default openssl_options to include +no_ticket, to reduce
    load on peers. Disable the session-cache too, which
    might reduce our load. Since we currrectly use a new
    context for every connection, both as server and client,
    there is no benefit for these.

  - Add $SOURCE_DATE_EPOCH support for reproducible builds,
    per spec at
    <https://reproducible-builds.org/specs/source-date-epoch
    />.

  - Fix smtp transport use of limited max_rcpt under
    mua_wrapper. Previously the check for any unsuccessful
    recipients did not notice the limit, and erroneously
    found still-pending ones.

  - Pipeline CHUNKING command and data together, on kernels
    that support MSG_MORE. Only in-clear (not on TLS
    connections).

  - Avoid using a temporary file during transport using
    dkim. Unless a transport-filter is involved we can
    buffer the headers in memory for creating the signature,
    and read the spool data file once for the signature and
    again for transmission.

  - Enable use of sendfile in Linux builds as default. It
    was disabled in 4.77 as the kernel support then wasn't
    solid, having issues in 64bit mode. Now, it's been long
    enough. Add support for FreeBSD also.

  - Add commandline_checks_require_admin option.

  - Do pipelining under TLS.

  - For the 'sock' variant of the malware scanner interface,
    accept an empty cmdline element to get the documented
    default one. Previously it was inaccessible.

  - Prevent repeated use of -p/-oMr

  - DKIM: enforce the DNS pubkey record 'h' permitted-hashes
    optional field, if present.

  - DKIM: when a message has multiple signatures matching an
    identity given in dkim_verify_signers, run the dkim acl
    once for each.

  - Support IDNA2008.

  - The path option on a pipe transport is now expanded
    before use

  - Have the EHLO response advertise VRFY, if there is a
    vrfy ACL defined.

  - Several bug fixes

  - Fix for buffer overflow in base64decode() (boo#1079832
    CVE-2018-6789)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185631");
  script_set_attribute(attribute:"see_also", value:"https://reproducible-builds.org/specs/source-date-epoch/");
  script_set_attribute(attribute:"solution", value:
"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-28026");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim 4.87 - 4.91 Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximstats-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"exim-4.94.2-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"exim-debuginfo-4.94.2-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"exim-debugsource-4.94.2-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eximon-4.94.2-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eximon-debuginfo-4.94.2-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eximstats-html-4.94.2-lp152.8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-debugsource / eximon / etc");
}
