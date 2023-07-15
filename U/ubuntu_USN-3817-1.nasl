#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3817-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118954);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-1000030", "CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-1061", "CVE-2018-14647");
  script_xref(name:"USN", value:"3817-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : Python vulnerabilities (USN-3817-1)");
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
"It was discovered that Python incorrectly handled large amounts of
data. A remote attacker could use this issue to cause Python to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2018-1000030)

It was discovered that Python incorrectly handled running external
commands in the shutil module. A remote attacker could use this issue
to cause Python to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2018-1000802)

It was discovered that Python incorrectly used regular expressions
vulnerable to catastrophic backtracking. A remote attacker could
possibly use this issue to cause a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2018-1060,
CVE-2018-1061)

It was discovered that Python failed to initialize Expat's hash salt.
A remote attacker could possibly use this issue to cause hash
collisions, leading to a denial of service. (CVE-2018-14647).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3817-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"python2.7", pkgver:"2.7.6-8ubuntu0.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python2.7-minimal", pkgver:"2.7.6-8ubuntu0.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3.4", pkgver:"3.4.3-1ubuntu1~14.04.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3.4-minimal", pkgver:"3.4.3-1ubuntu1~14.04.7")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python2.7", pkgver:"2.7.12-1ubuntu0~16.04.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python2.7-minimal", pkgver:"2.7.12-1ubuntu0~16.04.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3.5", pkgver:"3.5.2-2ubuntu0~16.04.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3.5-minimal", pkgver:"3.5.2-2ubuntu0~16.04.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python2.7", pkgver:"2.7.15~rc1-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python2.7-minimal", pkgver:"2.7.15~rc1-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2.7 / python2.7-minimal / python3.4 / python3.4-minimal / etc");
}
