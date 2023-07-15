#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3713-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111041);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-18248", "CVE-2018-4180", "CVE-2018-4181", "CVE-2018-6553");
  script_xref(name:"USN", value:"3713-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 / 18.04 LTS : CUPS vulnerabilities (USN-3713-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that CUPS incorrectly handled certain print jobs
with invalid usernames. A remote attacker could possibly use this
issue to cause CUPS to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 17.10 and Ubuntu 18.04
LTS. (CVE-2017-18248)

Dan Bastone discovered that the CUPS dnssd backend incorrectly handled
certain environment variables. A local attacker could possibly use
this issue to escalate privileges. (CVE-2018-4180)

Eric Rafaloff and John Dunlap discovered that CUPS incorrectly handled
certain include directives. A local attacker could possibly use this
issue to read arbitrary files. (CVE-2018-4181)

Dan Bastone discovered that the CUPS AppArmor profile incorrectly
confined the dnssd backend. A local attacker could possibly use this
issue to escape confinement. (CVE-2018-6553).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3713-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.10|18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10 / 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"cups", pkgver:"1.7.2-0ubuntu1.10")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"cups", pkgver:"2.1.3-4ubuntu0.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"cups", pkgver:"2.2.4-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"cups", pkgver:"2.2.7-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups");
}
