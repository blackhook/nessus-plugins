#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4471-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139784);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-15861", "CVE-2020-15862");
  script_xref(name:"USN", value:"4471-1");
  script_xref(name:"IAVA", value:"2020-A-0384-S");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 : Net-SNMP vulnerabilities (USN-4471-1)");
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
"Tobias Neitzel discovered that Net-SNMP incorrectly handled certain
symlinks. An attacker could possibly use this issue to access
sensitive information. (CVE-2020-15861) It was discovered that
Net-SNMP incorrectly handled certain inputs. An attacker could
possibly use this issue to execute arbitrary code. This issue only
affected Ubuntu 14.04 ESM, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and
Ubuntu 20.04 LTS. (CVE-2020-15862).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4471-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(12\.04|14\.04|16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 18.04 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"libsnmp-base", pkgver:"5.7.3+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libsnmp-perl", pkgver:"5.7.3+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libsnmp30", pkgver:"5.7.3+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"snmpd", pkgver:"5.7.3+dfsg-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libsnmp-base", pkgver:"5.7.3+dfsg-1.8ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libsnmp-perl", pkgver:"5.7.3+dfsg-1.8ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libsnmp30", pkgver:"5.7.3+dfsg-1.8ubuntu3.5")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"snmpd", pkgver:"5.7.3+dfsg-1.8ubuntu3.5")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libsnmp-base", pkgver:"5.8+dfsg-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libsnmp-perl", pkgver:"5.8+dfsg-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libsnmp35", pkgver:"5.8+dfsg-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"snmpd", pkgver:"5.8+dfsg-2ubuntu2.3")) flag++;

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsnmp-base / libsnmp-perl / libsnmp15 / libsnmp30 / libsnmp35 / etc");
}
