#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4337-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(135967);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2767", "CVE-2020-2773", "CVE-2020-2778", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2816", "CVE-2020-2830");
  script_xref(name:"USN", value:"4337-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 : OpenJDK vulnerabilities (USN-4337-1)");
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
"It was discovered that OpenJDK incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause a
denial of service while processing a specially crafted regular
expression. (CVE-2020-2754, CVE-2020-2755)

It was discovered that OpenJDK incorrectly handled class descriptors
and catching exceptions during object stream deserialization. An
attacker could possibly use this issue to cause a denial of service
while processing a specially crafted serialized input. (CVE-2020-2756,
CVE-2020-2757)

Bengt Jonsson, Juraj Somorovsky, Kostis Sagonas, Paul Fiterau Brostean
and Robert Merget discovered that OpenJDK incorrectly handled
certificate messages during TLS handshake. An attacker could possibly
use this issue to bypass certificate verification and insert, edit or
obtain sensitive information. This issue only affected OpenJDK 11.
(CVE-2020-2767)

It was discovered that OpenJDK incorrectly handled exceptions thrown
by unmarshalKeyInfo() and unmarshalXMLSignature(). An attacker could
possibly use this issue to cause a denial of service while reading key
info or XML signature data from XML input. (CVE-2020-2773)

Peter Dettman discovered that OpenJDK incorrectly handled
SSLParameters in setAlgorithmConstraints(). An attacker could possibly
use this issue to override the defined systems security policy and
lead to the use of weak crypto algorithms that should be disabled.
This issue only affected OpenJDK 11. (CVE-2020-2778)

Simone Bordet discovered that OpenJDK incorrectly re-used single null
TLS sessions for new TLS connections. A remote attacker could possibly
use this issue to cause a denial of service. (CVE-2020-2781)

Dan Amodio discovered that OpenJDK did not restrict the use of CR and
LF characters in values for HTTP headers. An attacker could possibly
use this issue to insert, edit or obtain sensitive information.
(CVE-2020-2800)

Nils Emmerich discovered that OpenJDK incorrectly checked boundaries
or argument types. An attacker could possibly use this issue to bypass
sandbox restrictions causing unspecified impact. (CVE-2020-2803,
CVE-2020-2805)

It was discovered that OpenJDK incorrectly handled application data
packets during TLS handshake. An attacker could possibly use this
issue to insert, edit or obtain sensitive information. This issue only
affected OpenJDK 11. (CVE-2020-2816)

It was discovered that OpenJDK incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause a
denial of service. (CVE-2020-2830).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4337-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");
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

if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk", pkgver:"8u252-b09-1~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre", pkgver:"8u252-b09-1~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u252-b09-1~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u252-b09-1~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u252-b09-1~16.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jdk", pkgver:"11.0.7+10-2ubuntu2~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre", pkgver:"11.0.7+10-2ubuntu2~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-headless", pkgver:"11.0.7+10-2ubuntu2~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-zero", pkgver:"11.0.7+10-2ubuntu2~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jdk", pkgver:"8u252-b09-1~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jre", pkgver:"8u252-b09-1~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u252-b09-1~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u252-b09-1~18.04")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jdk", pkgver:"11.0.7+10-2ubuntu2~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jre", pkgver:"11.0.7+10-2ubuntu2~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jre-headless", pkgver:"11.0.7+10-2ubuntu2~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jre-zero", pkgver:"11.0.7+10-2ubuntu2~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jdk", pkgver:"8u252-b09-1~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jre", pkgver:"8u252-b09-1~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jre-headless", pkgver:"8u252-b09-1~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jre-zero", pkgver:"8u252-b09-1~19.10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjdk-11-jdk / openjdk-11-jre / openjdk-11-jre-headless / etc");
}
