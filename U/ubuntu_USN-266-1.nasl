#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-266-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21183);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-1550");
  script_xref(name:"USN", value:"266-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : dia vulnerabilities (USN-266-1)");
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
"Three buffer overflows were discovered in the Xfig file format
importer. By tricking a user into opening a specially crafted .fig
file with dia, an attacker could exploit this to execute arbitrary
code with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dia-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dia-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dia-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2019 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"dia", pkgver:"0.93-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"dia-common", pkgver:"0.93-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"dia-gnome", pkgver:"0.93-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"dia-libs", pkgver:"0.93-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"dia", pkgver:"0.94.0-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"dia-common", pkgver:"0.94.0-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"dia-gnome", pkgver:"0.94.0-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"dia-libs", pkgver:"0.94.0-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dia", pkgver:"0.94.0-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dia-common", pkgver:"0.94.0-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dia-gnome", pkgver:"0.94.0-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dia-libs", pkgver:"0.94.0-11ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dia / dia-common / dia-gnome / dia-libs");
}
