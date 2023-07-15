#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3557-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106619);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-3948", "CVE-2018-1000024", "CVE-2018-1000027");
  script_xref(name:"USN", value:"3557-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : squid3 vulnerabilities (USN-3557-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Mathias Fischer discovered that Squid incorrectly handled certain long
strings in headers. A malicious remote server could possibly cause
Squid to crash, resulting in a denial of service. This issue was only
addressed in Ubuntu 16.04 LTS. (CVE-2016-2569)

William Lima discovered that Squid incorrectly handled XML parsing
when processing Edge Side Includes (ESI). A malicious remote server
could possibly cause Squid to crash, resulting in a denial of service.
This issue was only addressed in Ubuntu 16.04 LTS. (CVE-2016-2570)

Alex Rousskov discovered that Squid incorrectly handled
response-parsing failures. A malicious remote server could possibly
cause Squid to crash, resulting in a denial of service. This issue
only applied to Ubuntu 16.04 LTS. (CVE-2016-2571)

Santiago Ruano Rincon discovered that Squid incorrectly handled
certain Vary headers. A remote attacker could possibly use this issue
to cause Squid to crash, resulting in a denial of service. This issue
was only addressed in Ubuntu 16.04 LTS. (CVE-2016-3948)

Louis Dion-Marcil discovered that Squid incorrectly handled certain
Edge Side Includes (ESI) responses. A malicious remote server could
possibly cause Squid to crash, resulting in a denial of service.
(CVE-2018-1000024)

Louis Dion-Marcil discovered that Squid incorrectly handled certain
Edge Side Includes (ESI) responses. A malicious remote server could
possibly cause Squid to crash, resulting in a denial of service.
(CVE-2018-1000027).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3557-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected squid3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");
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

if (ubuntu_check(osver:"14.04", pkgname:"squid3", pkgver:"3.3.8-1ubuntu6.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"squid3", pkgver:"3.5.12-1ubuntu7.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"squid3", pkgver:"3.5.23-5ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid3");
}
