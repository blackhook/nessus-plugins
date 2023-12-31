#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-561-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29917);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2007-4897");
  script_xref(name:"USN", value:"561-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : pwlib vulnerability (USN-561-1)");
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
"Jose Miguel Esparza discovered that pwlib did not correctly handle
large string lengths. A remote attacker could send specially crafted
packets to applications linked against pwlib (e.g. Ekiga) causing them
to crash, leading to a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/561-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-1.10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-plugins-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-plugins-avc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-plugins-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-plugins-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-plugins-v4l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpt-plugins-v4l2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libpt-1.10.0", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-dbg", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-dev", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-doc", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-plugins-alsa", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-plugins-avc", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-plugins-dc", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-plugins-oss", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-plugins-v4l", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpt-plugins-v4l2", pkgver:"1.10.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-1.10.0", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-dbg", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-dev", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-doc", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-plugins-alsa", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-plugins-avc", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-plugins-dc", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-plugins-oss", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-plugins-v4l", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpt-plugins-v4l2", pkgver:"1.10.2.dfsg-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-1.10.0", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-dbg", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-dev", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-doc", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-plugins-alsa", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-plugins-avc", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-plugins-dc", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-plugins-oss", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-plugins-v4l", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpt-plugins-v4l2", pkgver:"1.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-1.10.0", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-dbg", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-dev", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-doc", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-plugins-alsa", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-plugins-avc", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-plugins-dc", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-plugins-oss", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-plugins-v4l", pkgver:"1.10.10-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpt-plugins-v4l2", pkgver:"1.10.10-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpt-1.10.0 / libpt-dbg / libpt-dev / libpt-doc / etc");
}
