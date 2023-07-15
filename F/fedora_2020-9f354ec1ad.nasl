#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-9f354ec1ad.
#

include("compat.inc");

if (description)
{
  script_id(141275);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/08");
  script_xref(name:"FEDORA", value:"2020-9f354ec1ad");

  script_name(english:"Fedora 33 : prosody (2020-9f354ec1ad)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Prosody 0.11.7 ==============

This is a security release for the 0.11.x stable branch. It is
strongly recommended that all users upgrade to this release,
especially those whose deployments have enabled `mod_websocket`.

As well as upgrading, we recommend all public deployments to review
and configure the `c2s_stanza_size_limit` and `s2s_stanza_size_limit`
options to values they are comfortable with. The value is specified in
bytes, and the XMPP specification requires values to be at least 10000
bytes, however it also recommends against just setting the limit to
10000 bytes. We are working to obtain data on real-world stanza sizes
in order to determine sensible defaults suitable for a future release.

Security ========

  - mod_websocket: Enforce size limits on received frames
    (fixes #1593)

Fixes and improvements ======================

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

Prosody 0.11.6 ==============

This release brings a collection of fixes and improvements added since
the 0.11.5 release improving security, performance, usability and
interoperability.

This version continues the deprecation of using `prosodyctl` to
start/stop Prosody.

Fixes and improvements ======================

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

Minor changes =============

  - net.http API: Add `request:cancel()` method

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

  - net.http: Re-expose `destroy_request()` function (fixes
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

  - Log warning when using `prosodyctl start/stop/restart`

  - core.certmanager: Look for `privkey.pem` to go with
    `fullchain.pem` (fixes #1526)

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
    logging (fix #1527: startup: Logging initialized twice)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-9f354ec1ad"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected prosody package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:prosody");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 33", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC33", reference:"prosody-0.11.7-1.fc33")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "prosody");
}
