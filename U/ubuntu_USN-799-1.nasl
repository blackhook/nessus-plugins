#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-799-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39786);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-1189");
  script_bugtraq_id(31602);
  script_xref(name:"USN", value:"799-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : dbus vulnerability (USN-799-1)");
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
"It was discovered that the D-Bus library did not correctly validate
signatures. If a local user sent a specially crafted D-Bus key, they
could spoof a valid signature and bypass security policies.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/799-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-1-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-glib-1-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-glib-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-qt-1-1c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbus-qt-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:monodoc-dbus-1-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/14");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"dbus", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dbus-1-doc", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dbus-1-utils", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-1-2", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-1-cil", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-1-dev", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-glib-1-2", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-glib-1-dev", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-qt-1-1c2", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbus-qt-1-dev", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"monodoc-dbus-1-manual", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dbus", pkgver:"0.60-6ubuntu8.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dbus", pkgver:"1.1.20-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dbus-1-doc", pkgver:"1.1.20-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dbus-x11", pkgver:"1.1.20-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdbus-1-3", pkgver:"1.1.20-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdbus-1-dev", pkgver:"1.1.20-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dbus", pkgver:"1.2.4-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dbus-1-doc", pkgver:"1.2.4-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dbus-x11", pkgver:"1.2.4-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdbus-1-3", pkgver:"1.2.4-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdbus-1-dev", pkgver:"1.2.4-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dbus", pkgver:"1.2.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dbus-1-doc", pkgver:"1.2.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dbus-x11", pkgver:"1.2.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libdbus-1-3", pkgver:"1.2.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libdbus-1-dev", pkgver:"1.2.12-0ubuntu2.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus / dbus-1-doc / dbus-1-utils / dbus-x11 / libdbus-1-2 / etc");
}
