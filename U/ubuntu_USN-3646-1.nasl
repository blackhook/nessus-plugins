#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3646-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109812);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-10545", "CVE-2018-10546", "CVE-2018-10547", "CVE-2018-10548", "CVE-2018-10549");
  script_xref(name:"USN", value:"3646-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 / 18.04 LTS : PHP vulnerabilities (USN-3646-1)");
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
"It was discovered that PHP incorrectly handled opcache access controls
when configured to use PHP-FPM. A local user could possibly use this
issue to obtain sensitive information from another user's PHP
applications. (CVE-2018-10545)

It was discovered that the PHP iconv stream filter incorrect handled
certain invalid multibyte sequences. A remote attacker could possibly
use this issue to cause PHP to hang, resulting in a denial of service.
(CVE-2018-10546)

It was discovered that the PHP PHAR error pages incorrectly filtered
certain data. A remote attacker could possibly use this issue to
perform a reflected XSS attack. (CVE-2018-10547)

It was discovered that PHP incorrectly handled LDAP. A malicious
remote LDAP server could possibly use this issue to cause PHP to
crash, resulting in a denial of service. (CVE-2018-10548)

It was discovered that PHP incorrectly handled certain exif tags in
JPEG images. A remote attacker could possibly use this issue to cause
PHP to crash, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS, Ubuntu 17.10, and Ubuntu 18.04 LTS.
(CVE-2018-10549).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3646-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.1-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.1-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.1-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-fpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/15");
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

if (ubuntu_check(osver:"14.04", pkgname:"libapache2-mod-php5", pkgver:"5.5.9+dfsg-1ubuntu4.25")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cgi", pkgver:"5.5.9+dfsg-1ubuntu4.25")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-cli", pkgver:"5.5.9+dfsg-1ubuntu4.25")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"php5-fpm", pkgver:"5.5.9+dfsg-1ubuntu4.25")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libapache2-mod-php7.0", pkgver:"7.0.30-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cgi", pkgver:"7.0.30-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cli", pkgver:"7.0.30-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-fpm", pkgver:"7.0.30-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libapache2-mod-php7.1", pkgver:"7.1.17-0ubuntu0.17.10.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"php7.1-cgi", pkgver:"7.1.17-0ubuntu0.17.10.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"php7.1-cli", pkgver:"7.1.17-0ubuntu0.17.10.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"php7.1-fpm", pkgver:"7.1.17-0ubuntu0.17.10.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libapache2-mod-php7.2", pkgver:"7.2.5-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-cgi", pkgver:"7.2.5-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-cli", pkgver:"7.2.5-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-fpm", pkgver:"7.2.5-0ubuntu0.18.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / libapache2-mod-php7.0 / libapache2-mod-php7.1 / etc");
}
