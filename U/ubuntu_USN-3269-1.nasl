#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3269-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99723);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-3302", "CVE-2017-3305", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3329", "CVE-2017-3331", "CVE-2017-3450", "CVE-2017-3453", "CVE-2017-3454", "CVE-2017-3455", "CVE-2017-3456", "CVE-2017-3457", "CVE-2017-3458", "CVE-2017-3459", "CVE-2017-3460", "CVE-2017-3461", "CVE-2017-3462", "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3465", "CVE-2017-3467", "CVE-2017-3468", "CVE-2017-3599", "CVE-2017-3600");
  script_xref(name:"USN", value:"3269-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : mysql-5.5, mysql-5.7 vulnerabilities (USN-3269-1) (Riddle)");
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
"Multiple security issues were discovered in MySQL and this update
includes new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.55 in Ubuntu 14.04 LTS. Ubuntu 16.04
LTS, Ubuntu 16.10 and Ubuntu 17.04 have been updated to MySQL 5.7.18.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-55.html
http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-18.html
http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618
.html.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3269-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected mysql-server-5.5 and / or mysql-server-5.7
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if (ubuntu_check(osver:"14.04", pkgname:"mysql-server-5.5", pkgver:"5.5.55-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"mysql-server-5.7", pkgver:"5.7.18-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"mysql-server-5.7", pkgver:"5.7.18-0ubuntu0.16.10.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"mysql-server-5.7", pkgver:"5.7.18-0ubuntu0.17.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-server-5.5 / mysql-server-5.7");
}
