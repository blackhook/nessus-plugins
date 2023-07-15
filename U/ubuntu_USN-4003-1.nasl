#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4003-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125705);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873");
  script_xref(name:"USN", value:"4003-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 18.10 : qtbase-opensource-src vulnerabilities (USN-4003-1)");
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
"It was discovered that Qt incorrectly handled certain XML documents. A
remote attacker could use this issue with a specially crafted XML
document to cause Qt to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2018-15518)

It was discovered that Qt incorrectly handled certain GIF images. A
remote attacker could use this issue with a specially crafted GIF
image to cause Qt to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2018-19870)

It was discovered that Qt incorrectly handled certain BMP images. A
remote attacker could use this issue with a specially crafted BMP
image to cause Qt to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2018-19873).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4003-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libqt5core5a and / or libqt5gui5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5core5a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5gui5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04|18\.04|18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"libqt5core5a", pkgver:"5.5.1+dfsg-16ubuntu7.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libqt5gui5", pkgver:"5.5.1+dfsg-16ubuntu7.6")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libqt5core5a", pkgver:"5.9.5+dfsg-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libqt5gui5", pkgver:"5.9.5+dfsg-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libqt5core5a", pkgver:"5.11.1+dfsg-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libqt5gui5", pkgver:"5.11.1+dfsg-7ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt5core5a / libqt5gui5");
}
