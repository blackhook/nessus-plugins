#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-465-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28065);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2007-1804");
  script_xref(name:"USN", value:"465-1");

  script_name(english:"Ubuntu 7.04 : pulseaudio vulnerability (USN-465-1)");
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
"Luigi Auriemma discovered multiple flaws in pulseaudio's network
processing code. If an unauthenticated attacker sent specially crafted
requests to the pulseaudio daemon, it would crash, resulting in a
denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/465-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-browse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse-mainloop-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpulse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/25");
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
if (! ereg(pattern:"^(7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.04", pkgname:"libpulse-browse0", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpulse-dev", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpulse-mainloop-glib0", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpulse0", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio-esound-compat", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio-module-gconf", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio-module-hal", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio-module-lirc", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio-module-x11", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio-module-zeroconf", pkgver:"0.9.5-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pulseaudio-utils", pkgver:"0.9.5-5ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpulse-browse0 / libpulse-dev / libpulse-mainloop-glib0 / etc");
}
