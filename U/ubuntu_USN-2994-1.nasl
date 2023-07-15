#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2994-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91499);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2015-8806", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4449", "CVE-2016-4483");
  script_xref(name:"USN", value:"2994-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : libxml2 vulnerabilities (USN-2994-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that libxml2 incorrectly handled certain malformed
documents. If a user or automated system were tricked into opening a
specially crafted document, an attacker could possibly cause libxml2
to crash, resulting in a denial of service. (CVE-2015-8806,
CVE-2016-2073, CVE-2016-3627, CVE-2016-3705, CVE-2016-4447)

It was discovered that libxml2 incorrectly handled certain malformed
documents. If a user or automated system were tricked into opening a
specially crafted document, an attacker could cause libxml2 to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2016-1762, CVE-2016-1834)

Mateusz Jurczyk discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could cause libxml2
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-1833, CVE-2016-1838, CVE-2016-1839)

Wei Lei and Liu Yang discovered that libxml2 incorrectly handled
certain malformed documents. If a user or automated system were
tricked into opening a specially crafted document, an attacker could
cause libxml2 to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-1835, CVE-2016-1837)

Wei Lei and Liu Yang discovered that libxml2 incorrectly handled
certain malformed documents. If a user or automated system were
tricked into opening a specially crafted document, an attacker could
cause libxml2 to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 14.04 LTS,
Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-1836)

Kostya Serebryany discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could cause libxml2
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-1840)

It was discovered that libxml2 would load certain XML external
entities. If a user or automated system were tricked into opening a
specially crafted document, an attacker could possibly obtain access
to arbitrary files or cause resource consumption. (CVE-2016-4449)

Gustavo Grieco discovered that libxml2 incorrectly handled certain
malformed documents. If a user or automated system were tricked into
opening a specially crafted document, an attacker could possibly cause
libxml2 to crash, resulting in a denial of service. (CVE-2016-4483).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2994-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libxml2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2023 Canonical, Inc. / NASL script (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
var release = chomp(release);
if (! preg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libxml2", pkgver:"2.7.8.dfsg-5.1ubuntu4.15")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libxml2", pkgver:"2.9.1+dfsg1-3ubuntu4.8")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libxml2", pkgver:"2.9.2+zdfsg1-4ubuntu0.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libxml2", pkgver:"2.9.3+dfsg1-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
