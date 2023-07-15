#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4298-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(134402);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-13734", "CVE-2019-13750", "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753", "CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19924", "CVE-2019-19925", "CVE-2019-19926", "CVE-2019-19959", "CVE-2019-20218", "CVE-2020-9327");
  script_xref(name:"USN", value:"4298-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 : SQLite vulnerabilities (USN-4298-1)");
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
"It was discovered that SQLite incorrectly handled certain shadow
tables. An attacker could use this issue to cause SQLite to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2019-13734, CVE-2019-13750, CVE-2019-13753)

It was discovered that SQLite incorrectly handled certain corrupt
records. An attacker could use this issue to cause SQLite to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2019-13751)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 19.10. (CVE-2019-19880)

It was discovered that SQLite incorrectly handled certain queries. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 19.10. (CVE-2019-19923)

It was discovered that SQLite incorrectly handled parser tree
rewriting. An attacker could use this issue to cause SQLite to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 19.10. (CVE-2019-19924)

It was discovered that SQLite incorrectly handled certain ZIP
archives. An attacker could use this issue to cause SQLite to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.10.
(CVE-2019-19925, CVE-2019-19959)

It was discovered that SQLite incorrectly handled errors during
parsing. An attacker could use this issue to cause SQLite to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2019-19926)

It was discovered that SQLite incorrectly handled parsing errors. An
attacker could use this issue to cause SQLite to crash, resulting in a
denial of service, or possibly execute arbitrary code.
(CVE-2019-20218)

It was discovered that SQLite incorrectly handled generated column
optimizations. An attacker could use this issue to cause SQLite to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS and Ubuntu 19.10.
(CVE-2020-9327).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4298-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libsqlite3-0 and / or sqlite3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sqlite3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(16\.04|18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"libsqlite3-0", pkgver:"3.11.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"sqlite3", pkgver:"3.11.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libsqlite3-0", pkgver:"3.22.0-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"sqlite3", pkgver:"3.22.0-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libsqlite3-0", pkgver:"3.29.0-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"sqlite3", pkgver:"3.29.0-2ubuntu0.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsqlite3-0 / sqlite3");
}
