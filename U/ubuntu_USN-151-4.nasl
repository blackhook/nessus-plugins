#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-151-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20552);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2005-1849", "CVE-2005-2096");
  script_xref(name:"USN", value:"151-4");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : rpm vulnerability (USN-151-4)");
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
"USN-148-1 and USN-151-1 fixed two security flaws in zlib, which could
be exploited to cause Denial of Service attacks or even arbitrary code
execution with malicious data streams.

Since lsb-rpm is statically linked against the zlib library, it is
also affected by these issues. The updated packagages have been
rebuilt against the fixed zlib.

Please note that lsb-rpm is not officially supported (it is in the
'universe' component of the archive).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librpm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lsb-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2019 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"4.10", pkgname:"librpm-dev", pkgver:"4.0.4-28ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"librpm4", pkgver:"4.0.4-28ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"lsb-rpm", pkgver:"4.0.4-28ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"rpm", pkgver:"4.0.4-28ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"librpm-dev", pkgver:"4.0.4-29ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"librpm4", pkgver:"4.0.4-29ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"lsb-rpm", pkgver:"4.0.4-29ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"rpm", pkgver:"4.0.4-29ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"librpm-dev", pkgver:"4.0.4-31ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"librpm4", pkgver:"4.0.4-31ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"lsb-rpm", pkgver:"4.0.4-31ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"rpm", pkgver:"4.0.4-31ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "librpm-dev / librpm4 / lsb-rpm / rpm");
}
