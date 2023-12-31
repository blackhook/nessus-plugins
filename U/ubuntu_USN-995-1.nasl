#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-995-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49764);
  script_version("1.15");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2007-6720", "CVE-2009-0179", "CVE-2009-3995", "CVE-2009-3996", "CVE-2009-3997", "CVE-2010-2546", "CVE-2010-2971");
  script_bugtraq_id(33235, 33240, 37374, 41917, 42464);
  script_xref(name:"USN", value:"995-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.04 / 9.10 : libmikmod vulnerabilities (USN-995-1)");
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
"It was discovered that libMikMod incorrectly handled songs with
different channel counts. If a user were tricked into opening a
crafted song file, an attacker could cause a denial of service.
(CVE-2007-6720)

It was discovered that libMikMod incorrectly handled certain malformed
XM files. If a user were tricked into opening a crafted XM file, an
attacker could cause a denial of service. (CVE-2009-0179)

It was discovered that libMikMod incorrectly handled certain malformed
Impulse Tracker files. If a user were tricked into opening a crafted
Impulse Tracker file, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-3995, CVE-2010-2546, CVE-2010-2971)

It was discovered that libMikMod incorrectly handled certain malformed
Ultratracker files. If a user were tricked into opening a crafted
Ultratracker file, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-3996).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/995-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmikmod2 and / or libmikmod2-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmikmod2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmikmod2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
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
if (! preg(pattern:"^(8\.04|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libmikmod2", pkgver:"3.1.11-6ubuntu3.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmikmod2-dev", pkgver:"3.1.11-a-6ubuntu3.8.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmikmod2", pkgver:"3.1.11-6ubuntu3.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmikmod2-dev", pkgver:"3.1.11-a-6ubuntu3.9.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmikmod2", pkgver:"3.1.11-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmikmod2-dev", pkgver:"3.1.11-a-6ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmikmod2 / libmikmod2-dev");
}
