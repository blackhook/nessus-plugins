#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1366-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57973);
  script_version("1.11");
  script_cvs_date("Date: 2019/10/16 10:34:22");

  script_cve_id("CVE-2012-0210", "CVE-2012-0211", "CVE-2012-0212");
  script_xref(name:"USN", value:"1366-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : devscripts vulnerabilities (USN-1366-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Wise discovered that debdiff did not properly sanitize its input
when processing .dsc and .changes files. If debdiff processed a
crafted file, an attacker could execute arbitrary code with the
privileges of the user invoking the program. (CVE-2012-0210)

Raphael Geissert discovered that debdiff did not properly sanitize its
input when processing source packages. If debdiff processed an
original source tarball, with crafted filenames in the top-level
directory, an attacker could execute arbitrary code with the
privileges of the user invoking the program. (CVE-2012-0211)

Raphael Geissert discovered that debdiff did not properly sanitize its
input when processing filename parameters. If debdiff processed a
crafted filename parameter, an attacker could execute arbitrary code
with the privileges of the user invoking the program. (CVE-2012-0212).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1366-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected devscripts package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:devscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2019 Canonical, Inc. / NASL script (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"devscripts", pkgver:"2.10.11ubuntu5.8.04.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"devscripts", pkgver:"2.10.61ubuntu5.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"devscripts", pkgver:"2.10.67ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"devscripts", pkgver:"2.10.69ubuntu2.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"devscripts", pkgver:"2.11.1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devscripts");
}
