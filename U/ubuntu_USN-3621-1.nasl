#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3621-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108879);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079");
  script_xref(name:"USN", value:"3621-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : ruby1.9.1, ruby2.0, ruby2.3 vulnerabilities (USN-3621-1)");
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
"It was discovered that Ruby incorrectly handled certain inputs. An
attacker could possibly use this to access sensitive information.
(CVE-2018-1000073)

It was discovered that Ruby incorrectly handled certain files. An
attacker could possibly use this to execute arbitrary code.
(CVE-2018-1000074)

It was discovered that Ruby incorrectly handled certain files. An
attacker could possibly use this to cause a denial of service.
(CVE-2018-1000075)

It was discovered that Ruby incorrectly handled certain crypto
signatures. An attacker could possibly use this to execute arbitrary
code. (CVE-2018-1000076)

It was discovered that Ruby incorrectly handled certain inputs. An
attacker could possibly use this to execute arbitrary code.
(CVE-2018-1000077, CVE-2018-1000078, CVE-2018-1000079).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3621-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");
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

if (ubuntu_check(osver:"14.04", pkgname:"libruby1.9.1", pkgver:"1.9.3.484-2ubuntu1.8")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libruby2.0", pkgver:"2.0.0.484-1ubuntu2.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ruby1.9.1", pkgver:"1.9.3.484-2ubuntu1.8")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ruby1.9.3", pkgver:"1.9.3.484-2ubuntu1.8")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ruby2.0", pkgver:"2.0.0.484-1ubuntu2.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libruby2.3", pkgver:"2.3.1-2~16.04.7")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ruby2.3", pkgver:"2.3.1-2~16.04.7")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libruby2.3", pkgver:"2.3.3-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"ruby2.3", pkgver:"2.3.3-1ubuntu1.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby1.9.1 / libruby2.0 / libruby2.3 / ruby1.9.1 / ruby1.9.3 / etc");
}
