#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-372-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27953);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-5456");
  script_bugtraq_id(20707);
  script_xref(name:"USN", value:"372-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS / 6.10 : imagemagick vulnerability (USN-372-1)");
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
"M. Joonas Pihlaja discovered that ImageMagick did not sufficiently
verify the validity of PALM and DCM images. When processing a
specially crafted image with an application that uses imagemagick,
this could be exploited to execute arbitrary code with the
application's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/372-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++9c2a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/01");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"imagemagick", pkgver:"6.0.6.2-2.1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick++6", pkgver:"6.0.6.2-2.1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick++6-dev", pkgver:"6.0.6.2-2.1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick6", pkgver:"6:6.0.6.2-2.1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick6-dev", pkgver:"6.0.6.2-2.1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perlmagick", pkgver:"6.0.6.2-2.1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"imagemagick", pkgver:"6.2.3.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick++6-dev", pkgver:"6.2.3.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick++6c2", pkgver:"6.2.3.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick6", pkgver:"6:6.2.3.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick6-dev", pkgver:"6.2.3.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perlmagick", pkgver:"6.2.3.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"imagemagick", pkgver:"6.2.4.5-0.6ubuntu0.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick++9-dev", pkgver:"6.2.4.5-0.6ubuntu0.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick++9c2a", pkgver:"6.2.4.5-0.6ubuntu0.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick9", pkgver:"6:6.2.4.5-0.6ubuntu0.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagick9-dev", pkgver:"6.2.4.5-0.6ubuntu0.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"perlmagick", pkgver:"6.2.4.5-0.6ubuntu0.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"imagemagick", pkgver:"6.2.4.5.dfsg1-0.10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmagick++9-dev", pkgver:"6.2.4.5.dfsg1-0.10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmagick++9c2a", pkgver:"6.2.4.5.dfsg1-0.10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmagick9", pkgver:"7:6.2.4.5.dfsg1-0.10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libmagick9-dev", pkgver:"6.2.4.5.dfsg1-0.10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"perlmagick", pkgver:"6.2.4.5.dfsg1-0.10ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / libmagick++6 / libmagick++6-dev / libmagick++6c2 / etc");
}
