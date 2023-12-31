#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1036-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51433);
  script_version("1.8");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_xref(name:"USN", value:"1036-1");

  script_name(english:"Ubuntu 10.10 : CUPS update (USN-1036-1)");
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
"Under certain circumstances, CUPS could start before its AppArmor
profile was loaded and therefore run unconfined. This update ensures
the AppArmor profile is loaded before CUPS starts.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1036-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupscgi1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsdriver1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsdriver1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsmime1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsppdc1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/06");
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
if (! preg(pattern:"^(10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"cups", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"cups-bsd", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"cups-client", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"cups-common", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"cups-dbg", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"cups-ppdc", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"cupsddk", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcups2", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcups2-dev", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupscgi1", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupscgi1-dev", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsdriver1", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsdriver1-dev", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsimage2", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsimage2-dev", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsmime1", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsmime1-dev", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsppdc1", pkgver:"1.4.4-6ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcupsppdc1-dev", pkgver:"1.4.4-6ubuntu2.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-bsd / cups-client / cups-common / cups-dbg / cups-ppdc / etc");
}
