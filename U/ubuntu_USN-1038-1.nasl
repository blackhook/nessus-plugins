#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1038-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51435);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2010-1679", "CVE-2011-0402");
  script_xref(name:"USN", value:"1038-1");

  script_name(english:"Ubuntu 9.10 / 10.04 LTS / 10.10 : dpkg vulnerability (USN-1038-1)");
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
"Jakub Wilk and Raphael Hertzog discovered that dpkg-source did not
correctly handle certain paths and symlinks when unpacking
source-format version 3.0 packages. If a user or an automated system
were tricked into unpacking a specially crafted source package, a
remote attacker could modify files outside the target unpack
directory, leading to a denial of service or potentially gaining
access to the system.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1038-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpkg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dselect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdpkg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdpkg-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"dpkg", pkgver:"1.15.4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dpkg-dev", pkgver:"1.15.4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dselect", pkgver:"1.15.4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dpkg", pkgver:"1.15.5.6ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dpkg-dev", pkgver:"1.15.5.6ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dselect", pkgver:"1.15.5.6ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dpkg", pkgver:"1.15.8.4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dpkg-dev", pkgver:"1.15.8.4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dselect", pkgver:"1.15.8.4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libdpkg-dev", pkgver:"1.15.8.4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libdpkg-perl", pkgver:"1.15.8.4ubuntu3.1")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dpkg / dpkg-dev / dselect / libdpkg-dev / libdpkg-perl");
}
