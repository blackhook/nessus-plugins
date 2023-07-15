#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3785-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117935);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-13144", "CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437", "CVE-2018-14551", "CVE-2018-16323", "CVE-2018-16640", "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645", "CVE-2018-16749", "CVE-2018-16750");
  script_xref(name:"USN", value:"3785-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : imagemagick vulnerabilities (USN-3785-1)");
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
"Due to a large number of issues discovered in GhostScript that prevent
it from being used by ImageMagick safely, this update includes a
default policy change that disables support for the Postscript and PDF
formats in ImageMagick. This policy can be overridden if necessary by
using an alternate ImageMagick policy configuration.

It was discovered that several memory leaks existed when handling
certain images in ImageMagick. An attacker could use this to cause a
denial of service. (CVE-2018-14434, CVE-2018-14435, CVE-2018-14436,
CVE-2018-14437, CVE-2018-16640, CVE-2018-16750)

It was discovered that ImageMagick did not properly initialize a
variable before using it when processing MAT images. An attacker could
use this to cause a denial of service or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-14551)

It was discovered that an information disclosure vulnerability existed
in ImageMagick when processing XBM images. An attacker could use this
to expose sensitive information. (CVE-2018-16323)

It was discovered that an out-of-bounds write vulnerability existed in
ImageMagick when handling certain images. An attacker could use this
to cause a denial of service or possibly execute arbitrary code.
(CVE-2018-16642)

It was discovered that ImageMagick did not properly check for errors
in some situations. An attacker could use this to cause a denial of
service. (CVE-2018-16643)

It was discovered that ImageMagick did not properly validate image
meta data in some situations. An attacker could use this to cause a
denial of service. (CVE-2018-16644)

It was discovered that ImageMagick did not prevent excessive memory
allocation when handling certain image types. An attacker could use
this to cause a denial of service. (CVE-2018-16645)

Sergej Schumilo and Cornelius Aschermann discovered that ImageMagick
did not properly check for NULL in some situations when processing PNG
images. An attacker could use this to cause a denial of service.
(CVE-2018-16749)

USN-3681-1 fixed vulnerabilities in Imagemagick. Unfortunately, the
fix for CVE-2017-13144 introduced a regression in ImageMagick in
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. This update reverts the fix for
CVE-2017-13144 for those releases.

We apologize for the inconvenience.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3785-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-5v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");
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

if (ubuntu_check(osver:"14.04", pkgname:"imagemagick", pkgver:"8:6.7.7.10-6ubuntu3.13")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagick++5", pkgver:"8:6.7.7.10-6ubuntu3.13")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5", pkgver:"8:6.7.7.10-6ubuntu3.13")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5-extra", pkgver:"8:6.7.7.10-6ubuntu3.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu5.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu5.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu5.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu5.13")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu5.13")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"imagemagick", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagick++-6.q16-7", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagickcore-6.q16-3", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagickcore-6.q16-3-extra", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / imagemagick-6.q16 / libmagick++-6.q16-5v5 / etc");
}
