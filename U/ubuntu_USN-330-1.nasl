#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-330-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27909);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
  script_xref(name:"USN", value:"330-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : tiff vulnerabilities (USN-330-1)");
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
"Tavis Ormandy discovered that the TIFF library did not sufficiently
check handled images for validity. By tricking an user or an automated
system into processing a specially crafted TIFF image, an attacker
could exploit these weaknesses to execute arbitrary code with the
target application's privileges.

This library is used in many client and server applications, thus you
should reboot your computer after the upgrade to ensure that all
running programs use the new version of the library.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/330-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iOS MobileMail LibTIFF Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiffxx0c2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libtiff-tools", pkgver:"3.6.1-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libtiff4", pkgver:"3.6.1-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libtiff4-dev", pkgver:"3.6.1-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libtiff-opengl", pkgver:"3.7.3-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libtiff-tools", pkgver:"3.7.3-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libtiff4", pkgver:"3.7.3-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libtiff4-dev", pkgver:"3.7.3-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libtiffxx0c2", pkgver:"3.7.3-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiff-opengl", pkgver:"3.7.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiff-tools", pkgver:"3.7.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiff4", pkgver:"3.7.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiff4-dev", pkgver:"3.7.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtiffxx0c2", pkgver:"3.7.4-1ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-opengl / libtiff-tools / libtiff4 / libtiff4-dev / etc");
}
