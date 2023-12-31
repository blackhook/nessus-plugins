#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-571-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(30042);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_xref(name:"USN", value:"571-2");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : xorg-server regression (USN-571-2)");
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
"USN-571-1 fixed vulnerabilities in X.org. The upstream fixes were
incomplete, and under certain situations, applications using the
MIT-SHM extension (e.g. Java, wxWidgets) would crash with BadAlloc X
errors. This update fixes the problem.

We apologize for the inconvenience.

Multiple overflows were discovered in the XFree86-Misc, XInput-Misc,
TOG-CUP, EVI, and MIT-SHM extensions which did not correctly validate
function arguments. An authenticated attacker could send specially
crafted requests and gain root privileges. (CVE-2007-5760,
CVE-2007-6427, CVE-2007-6428, CVE-2007-6429)

It was discovered that the X.org server did not use user
privileges when attempting to open security policy files.
Local attackers could exploit this to probe for files in
directories they would not normally be able to access.
(CVE-2007-5958)

It was discovered that the PCF font handling code did not
correctly validate the size of fonts. An authenticated
attacker could load a specially crafted font and gain
additional privileges. (CVE-2008-0006).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/571-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xprint-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/21");
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

if (ubuntu_check(osver:"6.06", pkgname:"xdmx", pkgver:"1.0.2-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xdmx-tools", pkgver:"1.0.2-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xnest", pkgver:"1.0.2-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xserver-xorg-core", pkgver:"1:1.0.2-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xserver-xorg-dev", pkgver:"1.0.2-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xvfb", pkgver:"1.0.2-0ubuntu10.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xdmx", pkgver:"1.1.1-0ubuntu12.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xdmx-tools", pkgver:"1.1.1-0ubuntu12.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xnest", pkgver:"1.1.1-0ubuntu12.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xserver-xephyr", pkgver:"1.1.1-0ubuntu12.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xserver-xorg-core", pkgver:"1:1.1.1-0ubuntu12.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xserver-xorg-dev", pkgver:"1.1.1-0ubuntu12.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xvfb", pkgver:"1.1.1-0ubuntu12.5")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xdmx", pkgver:"1.2.0-3ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xdmx-tools", pkgver:"1.2.0-3ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xnest", pkgver:"1.2.0-3ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xserver-xephyr", pkgver:"1.2.0-3ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xserver-xorg-core", pkgver:"2:1.2.0-3ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xserver-xorg-dev", pkgver:"1.2.0-3ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xvfb", pkgver:"1.2.0-3ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xdmx", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xdmx-tools", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xnest", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xprint", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xprint-common", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xserver-xephyr", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xserver-xorg-core", pkgver:"2:1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xserver-xorg-core-dbg", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xserver-xorg-dev", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xvfb", pkgver:"1.3.0.0.dfsg-12ubuntu8.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xdmx / xdmx-tools / xnest / xprint / xprint-common / xserver-xephyr / etc");
}
