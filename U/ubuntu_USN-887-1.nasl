#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-887-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44058);
  script_version("1.13");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2009-4012");
  script_xref(name:"USN", value:"887-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : libthai vulnerability (USN-887-1)");
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
"Tim Starling discovered that LibThai did not correctly handle long
strings. A remote attacker could use specially-formed strings to
execute arbitrary code with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/887-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libthai-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libthai-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libthai-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libthai0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2019 Canonical, Inc. / NASL script (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libthai-data", pkgver:"0.1.9-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libthai-dev", pkgver:"0.1.9-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libthai-doc", pkgver:"0.1.9-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libthai0", pkgver:"0.1.9-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libthai-data", pkgver:"0.1.9-4ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libthai-dev", pkgver:"0.1.9-4ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libthai-doc", pkgver:"0.1.9-4ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libthai0", pkgver:"0.1.9-4ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libthai-data", pkgver:"0.1.9-4ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libthai-dev", pkgver:"0.1.9-4ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libthai-doc", pkgver:"0.1.9-4ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libthai0", pkgver:"0.1.9-4ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libthai-data", pkgver:"0.1.12-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libthai-dev", pkgver:"0.1.12-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libthai-doc", pkgver:"0.1.12-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libthai0", pkgver:"0.1.12-1ubuntu0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libthai-data / libthai-dev / libthai-doc / libthai0");
}
