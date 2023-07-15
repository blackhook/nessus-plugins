#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2987-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91423);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2014-2497", "CVE-2014-9709", "CVE-2015-8874", "CVE-2015-8877", "CVE-2016-3074");
  script_xref(name:"USN", value:"2987-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : libgd2 vulnerabilities (USN-2987-1)");
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
"It was discovered that the GD library incorrectly handled certain
color tables in XPM images. If a user or automated system were tricked
into processing a specially crafted XPM image, an attacker could cause
a denial of service. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2014-2497)

It was discovered that the GD library incorrectly handled certain
malformed GIF images. If a user or automated system were tricked into
processing a specially crafted GIF image, an attacker could cause a
denial of service. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2014-9709)

It was discovered that the GD library incorrectly handled memory when
using gdImageFillToBorder(). A remote attacker could possibly use this
issue to cause a denial of service. (CVE-2015-8874)

It was discovered that the GD library incorrectly handled memory when
using gdImageScaleTwoPass(). A remote attacker could possibly use this
issue to cause a denial of service. This issue only applied to Ubuntu
14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2015-8877)

Hans Jerry Illikainen discovered that the GD library incorrectly
handled certain malformed GD images. If a user or automated system
were tricked into processing a specially crafted GD image, an attacker
could cause a denial of service or possibly execute arbitrary code.
(CVE-2016-3074).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2987-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libgd2-noxpm, libgd2-xpm and / or libgd3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-noxpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-xpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2023 Canonical, Inc. / NASL script (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libgd2-noxpm", pkgver:"2.0.36~rc1~dfsg-6ubuntu2.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgd2-xpm", pkgver:"2.0.36~rc1~dfsg-6ubuntu2.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgd3", pkgver:"2.1.0-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libgd3", pkgver:"2.1.1-4ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgd3", pkgver:"2.1.1-4ubuntu0.16.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgd2-noxpm / libgd2-xpm / libgd3");
}