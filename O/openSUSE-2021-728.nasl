#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-728.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149566);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/25");

  script_cve_id("CVE-2021-32917", "CVE-2021-32918", "CVE-2021-32919", "CVE-2021-32920");

  script_name(english:"openSUSE Security Update : prosody (openSUSE-2021-728)");
  script_summary(english:"Check for the openSUSE-2021-728 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for prosody fixes the following issues :

prosody was updated to 0.11.9 :

Security :

  - mod_limits, prosody.cfg.lua: Enable rate limits by
    default

  - certmanager: Disable renegotiation by default

  - mod_proxy65: Restrict access to local c2s connections by
    default

  - util.startup: Set more aggressive defaults for GC

  - mod_c2s, mod_s2s, mod_component, mod_bosh,
    mod_websockets: Set default stanza size limits

  - mod_authinternal(plain,hashed): Use constant-time string
    comparison for secrets

  - mod_dialback: Remove dialback-without-dialback feature

  - mod_dialback: Use constant-time comparison with hmac

Minor changes :

  - util.hashes: Add constant-time string comparison
    (binding to CRYPTO_memcmp)

  - mod_c2s: Don&rsquo;t throw errors in async code when
    connections are gone

  - mod_c2s: Fix traceback in session close when conn is nil

  - core.certmanager: Improve detection of LuaSec/OpenSSL
    capabilities

  - mod_saslauth: Use a defined SASL error

  - MUC: Add support for advertising
    muc#roomconfig_allowinvites in room disco#info

  - mod_saslauth: Don&rsquo;t throw errors in async code
    when connections are gone

  - mod_pep: Advertise base pubsub feature (fixes #1632:
    mod_pep missing pubsub feature in disco)

  - prosodyctl check config: Add &lsquo;gc&rsquo; to list of
    global options

  - prosodyctl about: Report libexpat version if known

  - util.xmppstream: Add API to dynamically configure the
    stanza size limit for a stream

  - util.set: Add is_set() to test if an object is a set

  - mod_http: Skip IP resolution in non-proxied case

  - mod_c2s: Log about missing conn on async state changes

  - util.xmppstream: Reduce internal default xmppstream
    limit to 1MB

Relevant: https://prosody.im/security/advisory_20210512

  - boo#1186027: Prosody XMPP server advisory 2021-05-12

  - CVE-2021-32919

  - CVE-2021-32917

  - CVE-2021-32917

  - CVE-2021-32920

  - CVE-2021-32918

Update to 0.11.8 :

Security :

  - mod_saslauth: Disable &lsquo;tls-unique&rsquo; channel
    binding with TLS 1.3 (#1542)

Fixes and improvements :

  - net.websocket.frames: Improve websocket masking
    performance by using the new util.strbitop

  - util.strbitop: Library for efficient bitwise operations
    on strings

Minor changes :

  - MUC: Correctly advertise whether the subject can be
    changed (#1155)

  - MUC: Preserve disco &lsquo;node&rsquo; attribute (or
    lack thereof) in responses (#1595)

  - MUC: Fix logic bug causing unnecessary presence to be
    sent (#1615)

  - mod_bosh: Fix error if client tries to connect to
    component (#425)

  - mod_bosh: Pick out the &lsquo;wait&rsquo; before
    checking it instead of earlier

  - mod_pep: Advertise base PubSub feature (#1632)

  - mod_pubsub: Fix notification stanza type setting (#1605)

  - mod_s2s: Prevent keepalives before client has
    established a stream

  - net.adns: Fix bug that sent empty DNS packets (#1619)

  - net.http.server: Don&rsquo;t send Content-Length on
    1xx/204 responses (#1596)

  - net.websocket.frames: Fix length calculation bug (#1598)

  - util.dbuffer: Make length API in line with Lua strings

  - util.dbuffer: Optimize substring operations

  - util.debug: Fix locals being reported under wrong stack
    frame in some cases

  - util.dependencies: Fix check for Lua bitwise operations
    library (#1594)

  - util.interpolation: Fix combination of filters and
    fallback values #1623

  - util.promise: Preserve tracebacks

  - util.stanza: Reject ASCII control characters (#1606)

  - timers: Ensure timers can&rsquo;t block other processing
    (#1620)

Update to 0.11.7 :

Security :

  - mod_websocket: Enforce size limits on received frames
    (fixes #1593)

Fixes and improvements :

  - mod_c2s, mod_s2s: Make stanza size limits configurable

  - Add configuration options to control Lua garbage
    collection parameters

  - net.http: Backport SNI support for outgoing HTTP
    requests (#409)

  - mod_websocket: Process all data in the buffer on close
    frame and connection errors (fixes #1474, #1234)

  - util.indexedbheap: Fix heap data structure corruption,
    causing some timers to fail after a reschedule (fixes
    #1572)

Update to 0.11.6 :

Fixes and improvements :

  - mod_storage_internal: Fix error in time limited queries
    on items without &lsquo;when&rsquo; field, fixes #1557

  - mod_carbons: Fix handling of incoming MUC PMs #1540

  - mod_csi_simple: Consider XEP-0353: Jingle Message
    Initiation important

  - mod_http_files: Avoid using inode in etag, fixes #1498:
    Fail to download file on FreeBSD

  - mod_admin_telnet: Create a DNS resolver per console
    session (fixes #1492: Telnet console DNS commands
    reduced usefulness)

  - core.certmanager: Move EECDH ciphers before EDH in
    default cipherstring (fixes #1513)

  - mod_s2s: Escape invalid XML in loggin (same way as
    mod_c2s) (fixes #1574: Invalid XML input on s2s
    connection is logged unescaped)

  - mod_muc: Allow control over the
    server-admins-are-room-owners feature (see #1174)

  - mod_muc_mam: Remove spoofed archive IDs before archiving
    (fixes #1552: MUC MAM may strip its own archive id)

  - mod_muc_mam: Fix stanza id filter event name, fixes
    #1546: mod_muc_mam does not strip spoofed stanza ids

  - mod_muc_mam: Fix missing advertising of XEP-0359, fixes
    #1547: mod_muc_mam does not advertise stanza-id

Minor changes :

  - net.http API: Add request:cancel() method

  - net.http API: Fix traceback on invalid URL passed to
    request()

  - MUC: Persist affiliation_data in new MUC format

  - mod_websocket: Fire event on session creation (thanks
    Aaron van Meerten)

  - MUC: Always include
    &lsquo;affiliation&rsquo;/&lsquo;role&rsquo; attributes,
    defaulting to &lsquo;none&rsquo; if nil

  - mod_tls: Log when certificates are (re)loaded

  - mod_vcard4: Report correct error condition (fixes #1521:
    mod_vcard4 reports wrong error)

  - net.http: Re-expose destroy_request() function (fixes
    unintentional API breakage)

  - net.http.server: Strip port from Host header in IPv6
    friendly way (fix #1302)

  - util.prosodyctl: Tell prosody do daemonize via command
    line flag (fixes #1514)

  - SASL: Apply saslprep where necessary, fixes #1560: Login
    fails if password contains special chars

  - net.http.server: Fix reporting of missing Host header

  - util.datamanager API: Fix iterating over
    &ldquo;users&rdquo; (thanks marc0s)

  - net.resolvers.basic: Default conn_type to
    &lsquo;tcp&rsquo; consistently if unspecified (thanks
    marc0s)

  - mod_storage_sql: Fix check for deletion limits (fixes
    #1494)

  - mod_admin_telnet: Handle unavailable cipher info (fixes
    #1510: mod_admin_telnet backtrace)

  - Log warning when using prosodyctl start/stop/restart

  - core.certmanager: Look for privkey.pem to go with
    fullchain.pem (fixes #1526)

  - mod_storage_sql: Add index covering sort_id to improve
    performance (fixes #1505)

  - mod_mam,mod_muc_mam: Allow other work to be performed
    during archive cleanup (fixes #1504)

  - mod_muc_mam: Don&rsquo;t strip MUC tags, fix #1567: MUC
    tags stripped by mod_muc_mam

  - mod_pubsub, mod_pep: Ensure correct number of children
    of (fixes #1496)

  - mod_register_ibr: Add FORM_TYPE as required by XEP-0077
    (fixes #1511)

  - mod_muc_mam: Fix traceback saving message from
    non-occupant (fixes #1497)

  - util.startup: Remove duplicated initialization of
    logging (fix #1527: startup: Logging initialized twice)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://prosody.im/security/advisory_20210512"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected prosody packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32919");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:prosody");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:prosody-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:prosody-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"prosody-0.11.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"prosody-debuginfo-0.11.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"prosody-debugsource-0.11.9-lp152.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "prosody / prosody-debuginfo / prosody-debugsource");
}
