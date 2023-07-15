##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5419-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161170);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2018-16881", "CVE-2019-17041", "CVE-2019-17042");
  script_xref(name:"USN", value:"5419-1");

  script_name(english:"Ubuntu 16.04 LTS : Rsyslog vulnerabilities (USN-5419-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5419-1 advisory.

  - A denial of service vulnerability was found in rsyslog in the imptcp module. An attacker could send a
    specially crafted message to the imptcp socket, which would cause rsyslog to crash. Versions before 8.27.0
    are vulnerable. (CVE-2018-16881)

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmaixforwardedfrom/pmaixforwardedfrom.c has a heap
    overflow in the parser for AIX log messages. The parser tries to locate a log message delimiter (in this
    case, a space or a colon) but fails to account for strings that do not satisfy this constraint. If the
    string does not match, then the variable lenMsg will reach the value zero and will skip the sanity check
    that detects invalid log messages. The message will then be considered valid, and the parser will eat up
    the nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was
    zero and now becomes minus one. The following step in the parser is to shift left the contents of the
    message. To do this, it will call memmove with the right pointers to the target and destination strings,
    but the lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17041)

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmcisconames/pmcisconames.c has a heap overflow in
    the parser for Cisco log messages. The parser tries to locate a log message delimiter (in this case, a
    space or a colon), but fails to account for strings that do not satisfy this constraint. If the string
    does not match, then the variable lenMsg will reach the value zero and will skip the sanity check that
    detects invalid log messages. The message will then be considered valid, and the parser will eat up the
    nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was zero
    and now becomes minus one. The following step in the parser is to shift left the contents of the message.
    To do this, it will call memmove with the right pointers to the target and destination strings, but the
    lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17042)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5419-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rsyslog-relp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'rsyslog', 'pkgver': '8.16.0-1ubuntu3.1+esm1'},
    {'osver': '16.04', 'pkgname': 'rsyslog-elasticsearch', 'pkgver': '8.16.0-1ubuntu3.1+esm1'},
    {'osver': '16.04', 'pkgname': 'rsyslog-gnutls', 'pkgver': '8.16.0-1ubuntu3.1+esm1'},
    {'osver': '16.04', 'pkgname': 'rsyslog-gssapi', 'pkgver': '8.16.0-1ubuntu3.1+esm1'},
    {'osver': '16.04', 'pkgname': 'rsyslog-mysql', 'pkgver': '8.16.0-1ubuntu3.1+esm1'},
    {'osver': '16.04', 'pkgname': 'rsyslog-pgsql', 'pkgver': '8.16.0-1ubuntu3.1+esm1'},
    {'osver': '16.04', 'pkgname': 'rsyslog-relp', 'pkgver': '8.16.0-1ubuntu3.1+esm1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rsyslog / rsyslog-elasticsearch / rsyslog-gnutls / rsyslog-gssapi / etc');
}
