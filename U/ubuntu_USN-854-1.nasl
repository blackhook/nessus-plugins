#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-854-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42407);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2009-3293", "CVE-2009-3546");
  script_bugtraq_id(24651, 36712);
  script_xref(name:"USN", value:"854-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : libgd2 vulnerabilities (USN-854-1)");
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
"Tomas Hoger discovered that the GD library did not properly handle the
number of colors in certain malformed GD images. If a user or
automated system were tricked into processing a specially crafted GD
image, an attacker could cause a denial of service or possibly execute
arbitrary code. (CVE-2009-3546)

It was discovered that the GD library did not properly handle
incorrect color indexes. An attacker could send specially crafted
input to applications linked against libgd2 and cause a denial of
service or possibly execute arbitrary code. This issue only affected
Ubuntu 6.06 LTS. (CVE-2009-3293)

It was discovered that the GD library did not properly handle certain
malformed GIF images. If a user or automated system were tricked into
processing a specially crafted GIF image, an attacker could cause a
denial of service. This issue only affected Ubuntu 6.06 LTS.
(CVE-2007-3475, CVE-2007-3476)

It was discovered that the GD library did not properly handle large
angle degree values. An attacker could send specially crafted input to
applications linked against libgd2 and cause a denial of service. This
issue only affected Ubuntu 6.06 LTS. (CVE-2007-3477).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/854-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-noxpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-noxpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-xpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-xpm-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2019 Canonical, Inc. / NASL script (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
release = chomp(release);
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libgd-tools", pkgver:"2.0.33-2ubuntu5.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgd2", pkgver:"2.0.33-2ubuntu5.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgd2-dev", pkgver:"2.0.33-2ubuntu5.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgd2-noxpm", pkgver:"2.0.33-2ubuntu5.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgd2-noxpm-dev", pkgver:"2.0.33-2ubuntu5.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgd2-xpm", pkgver:"2.0.33-2ubuntu5.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgd2-xpm-dev", pkgver:"2.0.33-2ubuntu5.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgd-tools", pkgver:"2.0.35.dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgd2-noxpm", pkgver:"2.0.35.dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgd2-noxpm-dev", pkgver:"2.0.35.dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgd2-xpm", pkgver:"2.0.35.dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgd2-xpm-dev", pkgver:"2.0.35.dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgd-tools", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgd2-noxpm", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgd2-noxpm-dev", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgd2-xpm", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgd2-xpm-dev", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgd-tools", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgd2-noxpm", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgd2-noxpm-dev", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgd2-xpm", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgd2-xpm-dev", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgd-tools", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgd2-noxpm", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgd2-noxpm-dev", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgd2-xpm", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgd2-xpm-dev", pkgver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgd-tools / libgd2 / libgd2-dev / libgd2-noxpm / libgd2-noxpm-dev / etc");
}
