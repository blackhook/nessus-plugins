#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3253-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100677);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566");
  script_xref(name:"USN", value:"3253-2");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : nagios3 regression (USN-3253-2)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"USN-3253-1 fixed vulnerabilities in Nagios. The update prevented log
files from being displayed in the web interface. This update fixes the
problem.

We apologize for the inconvenience.

It was discovered that Nagios incorrectly handled certain long
strings. A remote authenticated attacker could use this issue to cause
Nagios to crash, resulting in a denial of service, or possibly obtain
sensitive information. (CVE-2013-7108, CVE-2013-7205)

It was discovered that Nagios incorrectly handled certain
long messages to cmd.cgi. A remote attacker could possibly
use this issue to cause Nagios to crash, resulting in a
denial of service. (CVE-2014-1878)

Dawid Golunski discovered that Nagios incorrectly handled
symlinks when accessing log files. A local attacker could
possibly use this issue to elevate privileges. In the
default installation of Ubuntu, this should be prevented by
the Yama link restrictions. (CVE-2016-9566).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3253-2/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nagios3-cgi and / or nagios3-core packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nagios3-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nagios3-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/08");
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
if (! preg(pattern:"^(14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"nagios3-cgi", pkgver:"3.5.1-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nagios3-core", pkgver:"3.5.1-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"nagios3-cgi", pkgver:"3.5.1.dfsg-2.1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"nagios3-core", pkgver:"3.5.1.dfsg-2.1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"nagios3-cgi", pkgver:"3.5.1.dfsg-2.1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"nagios3-core", pkgver:"3.5.1.dfsg-2.1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"nagios3-cgi", pkgver:"3.5.1.dfsg-2.1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"nagios3-core", pkgver:"3.5.1.dfsg-2.1ubuntu5.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios3-cgi / nagios3-core");
}
