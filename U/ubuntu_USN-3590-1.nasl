#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3590-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107193);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-7050", "CVE-2018-7051", "CVE-2018-7052", "CVE-2018-7053", "CVE-2018-7054", "CVE-2018-7073");
  script_xref(name:"TRA", value:"TRA-2018-15");
  script_xref(name:"USN", value:"3590-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : irssi vulnerabilities (USN-3590-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that Irssi incorrectly handled certain empty nick
names. An attacker could possibly use this issue to cause a denial of
service. (CVE-2018-7050)

It was discovered that Irssi incorrectly handled certain nick names.
An attacker could possibly use this to access sensitive information.
(CVE-2018-7051)

It was discovered that Irssi incorrectly handled an increase in the
number of windows. An attacker could possibly use this issue to cause
a denial of service. (CVE-2018-7052)

It was discovered that Irssi incorrectly handled certain messages. An
attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 17.10. (CVE-2018-7053)

It was discovered that Irssi incorrectly handled certain
disconnections. An attacker could possibly use this to cause a denial
of service or execute arbitrary code. This issue only affected Ubuntu
17.10. (CVE-2018-7054).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3590-1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2018-15"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected irssi package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irssi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/07");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"irssi", pkgver:"0.8.15-5ubuntu3.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"irssi", pkgver:"0.8.19-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"irssi", pkgver:"1.0.4-1ubuntu2.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi");
}
