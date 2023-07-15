#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4239-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132953);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-11045", "CVE-2019-11046", "CVE-2019-11047", "CVE-2019-11050");
  script_xref(name:"USN", value:"4239-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.04 / 19.10 : PHP vulnerabilities (USN-4239-1)");
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
"It was discovered that PHP incorrectly handled certain files. An
attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 14.04 ESM, 16.04 LTS, 18.04 LTS, 19.04
and 19.10. (CVE-2019-11045)

It was discovered that PHP incorrectly handled certain inputs. An
attacker could possibly use this issue to expose sensitive
information. (CVE-2019-11046)

It was discovered that PHP incorrectly handled certain images. An
attacker could possibly use this issue to access sensitive
information. (CVE-2019-11047, CVE-2019-11050).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4239-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11050");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.3-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.3-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.3-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.3-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.3-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");
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
if (! preg(pattern:"^(12\.04|14\.04|16\.04|18\.04|19\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 18.04 / 19.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"libapache2-mod-php7.0", pkgver:"7.0.33-0ubuntu0.16.04.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-bcmath", pkgver:"7.0.33-0ubuntu0.16.04.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cgi", pkgver:"7.0.33-0ubuntu0.16.04.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-cli", pkgver:"7.0.33-0ubuntu0.16.04.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-fpm", pkgver:"7.0.33-0ubuntu0.16.04.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-mbstring", pkgver:"7.0.33-0ubuntu0.16.04.9")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"php7.0-xmlrpc", pkgver:"7.0.33-0ubuntu0.16.04.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libapache2-mod-php7.2", pkgver:"7.2.24-0ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-bcmath", pkgver:"7.2.24-0ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-cgi", pkgver:"7.2.24-0ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-cli", pkgver:"7.2.24-0ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-fpm", pkgver:"7.2.24-0ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-mbstring", pkgver:"7.2.24-0ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"php7.2-xmlrpc", pkgver:"7.2.24-0ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libapache2-mod-php7.2", pkgver:"7.2.24-0ubuntu0.19.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"php7.2-bcmath", pkgver:"7.2.24-0ubuntu0.19.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"php7.2-cgi", pkgver:"7.2.24-0ubuntu0.19.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"php7.2-cli", pkgver:"7.2.24-0ubuntu0.19.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"php7.2-fpm", pkgver:"7.2.24-0ubuntu0.19.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"php7.2-mbstring", pkgver:"7.2.24-0ubuntu0.19.04.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"php7.2-xmlrpc", pkgver:"7.2.24-0ubuntu0.19.04.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libapache2-mod-php7.3", pkgver:"7.3.11-0ubuntu0.19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"php7.3-bcmath", pkgver:"7.3.11-0ubuntu0.19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"php7.3-cgi", pkgver:"7.3.11-0ubuntu0.19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"php7.3-cli", pkgver:"7.3.11-0ubuntu0.19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"php7.3-fpm", pkgver:"7.3.11-0ubuntu0.19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"php7.3-mbstring", pkgver:"7.3.11-0ubuntu0.19.10.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"php7.3-xmlrpc", pkgver:"7.3.11-0ubuntu0.19.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / libapache2-mod-php7.0 / libapache2-mod-php7.2 / etc");
}
