#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3279-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100098);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-8743");
  script_xref(name:"USN", value:"3279-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 : apache2 vulnerabilities (USN-3279-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that the Apache mod_session_crypto module was
encrypting data and cookies using either CBC or ECB modes. A remote
attacker could possibly use this issue to perform padding oracle
attacks. (CVE-2016-0736)

Maksim Malyutin discovered that the Apache mod_auth_digest module
incorrectly handled malicious input. A remote attacker could possibly
use this issue to cause Apache to crash, resulting in a denial of
service. (CVE-2016-2161)

David Dennerline and Regis Leroy discovered that the Apache HTTP
Server incorrectly handled unusual whitespace when parsing requests,
contrary to specifications. When being used in combination with a
proxy or backend server, a remote attacker could possibly use this
issue to perform an injection attack and pollute cache. This update
may introduce compatibility issues with clients that do not strictly
follow HTTP protocol specifications. A new configuration option
'HttpProtocolOptions Unsafe' can be used to revert to the previous
unsafe behaviour in problematic environments. (CVE-2016-8743).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3279-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected apache2-bin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"apache2-bin", pkgver:"2.4.7-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"apache2-bin", pkgver:"2.4.18-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"apache2-bin", pkgver:"2.4.18-2ubuntu4.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-bin");
}
