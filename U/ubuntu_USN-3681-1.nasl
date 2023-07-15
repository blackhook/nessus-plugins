#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3681-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110516);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-10995", "CVE-2017-11352", "CVE-2017-11533", "CVE-2017-11535", "CVE-2017-11537", "CVE-2017-11639", "CVE-2017-11640", "CVE-2017-12140", "CVE-2017-12418", "CVE-2017-12429", "CVE-2017-12430", "CVE-2017-12431", "CVE-2017-12432", "CVE-2017-12433", "CVE-2017-12435", "CVE-2017-12563", "CVE-2017-12587", "CVE-2017-12640", "CVE-2017-12643", "CVE-2017-12644", "CVE-2017-12670", "CVE-2017-12674", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-12875", "CVE-2017-12877", "CVE-2017-12983", "CVE-2017-13058", "CVE-2017-13059", "CVE-2017-13060", "CVE-2017-13061", "CVE-2017-13062", "CVE-2017-13131", "CVE-2017-13134", "CVE-2017-13139", "CVE-2017-13142", "CVE-2017-13143", "CVE-2017-13144", "CVE-2017-13145", "CVE-2017-13758", "CVE-2017-13768", "CVE-2017-13769", "CVE-2017-14060", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14174", "CVE-2017-14175", "CVE-2017-14224", "CVE-2017-14249", "CVE-2017-14325", "CVE-2017-14326", "CVE-2017-14341", "CVE-2017-14342", "CVE-2017-14343", "CVE-2017-14400", "CVE-2017-14505", "CVE-2017-14531", "CVE-2017-14532", "CVE-2017-14533", "CVE-2017-14607", "CVE-2017-14624", "CVE-2017-14625", "CVE-2017-14626", "CVE-2017-14682", "CVE-2017-14684", "CVE-2017-14739", "CVE-2017-14741", "CVE-2017-14989", "CVE-2017-15015", "CVE-2017-15016", "CVE-2017-15017", "CVE-2017-15032", "CVE-2017-15033", "CVE-2017-15217", "CVE-2017-15218", "CVE-2017-15277", "CVE-2017-15281", "CVE-2017-16546", "CVE-2017-17499", "CVE-2017-17504", "CVE-2017-17680", "CVE-2017-17681", "CVE-2017-17682", "CVE-2017-17879", "CVE-2017-17881", "CVE-2017-17882", "CVE-2017-17884", "CVE-2017-17885", "CVE-2017-17886", "CVE-2017-17887", "CVE-2017-17914", "CVE-2017-17934", "CVE-2017-18008", "CVE-2017-18022", "CVE-2017-18027", "CVE-2017-18028", "CVE-2017-18029", "CVE-2017-18209", "CVE-2017-18211", "CVE-2017-18251", "CVE-2017-18252", "CVE-2017-18254", "CVE-2017-18271", "CVE-2017-18273", "CVE-2018-10177", "CVE-2018-10804", "CVE-2018-10805", "CVE-2018-11251", "CVE-2018-11625", "CVE-2018-11655", "CVE-2018-11656", "CVE-2018-5246", "CVE-2018-5247", "CVE-2018-5248", "CVE-2018-5357", "CVE-2018-5358", "CVE-2018-6405", "CVE-2018-7443", "CVE-2018-8804", "CVE-2018-8960", "CVE-2018-9133");
  script_xref(name:"USN", value:"3681-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 / 18.04 LTS : ImageMagick vulnerabilities (USN-3681-1)");
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
"It was discovered that ImageMagick incorrectly handled certain
malformed image files. If a user or automated system using ImageMagick
were tricked into opening a specially crafted image, an attacker could
exploit this to cause a denial of service or possibly execute code
with the privileges of the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3681-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/13");
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

if (ubuntu_check(osver:"14.04", pkgname:"imagemagick", pkgver:"8:6.7.7.10-6ubuntu3.11")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagick++5", pkgver:"8:6.7.7.10-6ubuntu3.11")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5", pkgver:"8:6.7.7.10-6ubuntu3.11")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5-extra", pkgver:"8:6.7.7.10-6ubuntu3.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu5.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu5.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu5.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu5.11")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu5.11")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"imagemagick", pkgver:"8:6.9.7.4+dfsg-16ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"imagemagick-6.q16", pkgver:"8:6.9.7.4+dfsg-16ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libmagick++-6.q16-7", pkgver:"8:6.9.7.4+dfsg-16ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libmagickcore-6.q16-3", pkgver:"8:6.9.7.4+dfsg-16ubuntu2.2")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libmagickcore-6.q16-3-extra", pkgver:"8:6.9.7.4+dfsg-16ubuntu2.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"imagemagick", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagick++-6.q16-7", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagickcore-6.q16-3", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmagickcore-6.q16-3-extra", pkgver:"8:6.9.7.4+dfsg-16ubuntu6.2")) flag++;

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
