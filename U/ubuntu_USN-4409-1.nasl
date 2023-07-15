#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4409-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138134);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-10730", "CVE-2020-10745", "CVE-2020-10760");
  script_xref(name:"USN", value:"4409-1");
  script_xref(name:"IAVA", value:"2020-A-0288-S");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 / 20.04 : Samba vulnerabilities (USN-4409-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Andrew Bartlett discovered that Samba incorrectly handled certain LDAP
queries. A remote attacker could use this issue to cause Samba to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 19.10 and
Ubuntu 20.04 LTS. (CVE-2020-10730) Douglas Bagnall discovered that
Samba incorrectly handled certain queries. A remote attacker could
possibly use this issue to cause a denial of service. (CVE-2020-10745)
Andrei Popa discovered that Samba incorrectly handled certain LDAP
queries. A remote attacker could use this issue to cause Samba to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 19.10 and
Ubuntu 20.04 LTS. (CVE-2020-10760).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4409-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected samba package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10745");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/06");
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
if (! preg(pattern:"^(12\.04|14\.04|16\.04|18\.04|19\.10|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 18.04 / 19.10 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"samba", pkgver:"2:4.3.11+dfsg-0ubuntu0.16.04.28")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"samba", pkgver:"2:4.7.6+dfsg~ubuntu-0ubuntu2.17")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"samba", pkgver:"2:4.10.7+dfsg-0ubuntu2.6")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"samba", pkgver:"2:4.11.6+dfsg-0ubuntu1.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
