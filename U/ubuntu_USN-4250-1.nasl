#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4250-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133289);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-2570", "CVE-2020-2572", "CVE-2020-2573", "CVE-2020-2574", "CVE-2020-2577", "CVE-2020-2579", "CVE-2020-2584", "CVE-2020-2588", "CVE-2020-2589", "CVE-2020-2627", "CVE-2020-2660", "CVE-2020-2679", "CVE-2020-2686", "CVE-2020-2694");
  script_xref(name:"USN", value:"4250-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 : MySQL vulnerabilities (USN-4250-1)");
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

MySQL has been updated to 8.0.19 in Ubuntu 19.10. Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS have been updated to MySQL 5.7.29.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-29.html
https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-19.html
https://www.oracle.com/security-alerts/cpujan2020.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4250-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected mysql-server-5.7 and / or mysql-server-8.0
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2572");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"mysql-server-5.7", pkgver:"5.7.29-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mysql-server-5.7", pkgver:"5.7.29-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mysql-server-8.0", pkgver:"8.0.19-0ubuntu0.19.10.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-server-5.7 / mysql-server-8.0");
}
