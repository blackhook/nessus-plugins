#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1229.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118344);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11469", "CVE-2018-14645");

  script_name(english:"openSUSE Security Update : haproxy (openSUSE-2018-1229)");
  script_summary(english:"Check for the openSUSE-2018-1229 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for haproxy to version 1.8.14 fixes the following issues :

These security issues were fixed :

  - CVE-2018-14645: A flaw was discovered in the HPACK
    decoder what caused an out-of-bounds read in
    hpack_valid_idx() that resulted in a remote crash and
    denial of service (bsc#1108683)

  - CVE-2018-11469: Incorrect caching of responses to
    requests including an Authorization header allowed
    attackers to achieve information disclosure via an
    unauthenticated remote request (bsc#1094846).

These non-security issues were fixed :

  - Require apparmor-abstractions to reduce dependencies
    (bsc#1100787)

  - hpack: fix improper sign check on the header index value

  - cli: make sure the 'getsock' command is only called on
    connections

  - tools: fix set_net_port() / set_host_port() on IPv4

  - patterns: fix possible double free when reloading a
    pattern list

  - server: Crash when setting FQDN via CLI.

  - kqueue: Don't reset the changes number by accident.

  - snapshot: take the proxy's lock while dumping errors

- http/threads: atomically increment the error snapshot ID

  - dns: check and link servers' resolvers right after
    config parsing

  - h2: fix risk of memory leak on malformated wrapped
    frames

  - session: fix reporting of handshake processing time in
    the logs

  - stream: use atomic increments for the request counter

  - thread: implement HA_ATOMIC_XADD()

  - ECC cert should work with TLS < v1.2 and openssl >=
    1.1.1

  - dns/server: fix incomatibility between SRV resolution
    and server state file

  - hlua: Don't call RESET_SAFE_LJMP if SET_SAFE_LJMP
    returns 0.

  - thread: lua: Wrong SSL context initialization.

  - hlua: Make sure we drain the output buffer when done.

  - lua: reset lua transaction between http requests

  - mux_pt: dereference the connection with care in
    mux_pt_wake()

  - lua: Bad HTTP client request duration.

  - unix: provide a ->drain() function

  - Fix spelling error in configuration doc

  - cli/threads: protect some server commands against
    concurrent operations

  - cli/threads: protect all 'proxy' commands against
    concurrent updates

  - lua: socket timeouts are not applied

  - ssl: Use consistent naming for TLS protocols

  - dns: explain set server ... fqdn requires resolver

  - map: fix map_regm with backref

  - ssl: loading dh param from certifile causes
    unpredictable error.

  - ssl: fix missing error loading a keytype cert from a
    bundle.

  - ssl: empty connections reported as errors.

  - cli: make 'show fd' thread-safe

  - hathreads: implement a more flexible rendez-vous point

  - threads: fix the no-thread case after the change to the
    sync point

  - threads: add more consistency between certain variables
    in no-thread case

  - threads: fix the double CAS implementation for ARMv7

  - threads: Introduce double-width CAS on x86_64 and arm.

  - lua: possible CLOSE-WAIT state with '\n' headers

For additional changes please refer to the changelog.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108683"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected haproxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:haproxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"haproxy-1.8.14~git0.52e4d43b-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"haproxy-debuginfo-1.8.14~git0.52e4d43b-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"haproxy-debugsource-1.8.14~git0.52e4d43b-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "haproxy / haproxy-debuginfo / haproxy-debugsource");
}
