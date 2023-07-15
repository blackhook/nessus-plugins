#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4257-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133353);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-2583", "CVE-2020-2590", "CVE-2020-2593", "CVE-2020-2601", "CVE-2020-2604", "CVE-2020-2654", "CVE-2020-2655", "CVE-2020-2659");
  script_xref(name:"USN", value:"4257-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 : OpenJDK vulnerabilities (USN-4257-1)");
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
"It was discovered that OpenJDK incorrectly handled exceptions during
deserialization in BeanContextSupport. An attacker could possibly use
this issue to cause a denial of service or other unspecified impact.
(CVE-2020-2583)

It was discovered that OpenJDK incorrectly validated properties of
SASL messages included in Kerberos GSSAPI. An unauthenticated remote
attacker with network access via Kerberos could possibly use this
issue to insert, modify or obtain sensitive information.
(CVE-2020-2590)

It was discovered that OpenJDK incorrectly validated URLs. An attacker
could possibly use this issue to insert, edit or obtain sensitive
information. (CVE-2020-2593)

It was discovered that OpenJDK Security component still used MD5
algorithm. A remote attacker could possibly use this issue to obtain
sensitive information. (CVE-2020-2601)

It was discovered that OpenJDK incorrectly handled the application of
serialization filters. An attacker could possibly use this issue to
bypass the intended filter during serialization. (CVE-2020-2604)

Bo Zhang and Long Kuan discovered that OpenJDK incorrectly handled
X.509 certificates. An attacker could possibly use this issue to cause
a denial of service. (CVE-2020-2654)

Bengt Jonsson, Juraj Somorovsky, Kostis Sagonas, Paul Fiterau Brostean
and Robert Merget discovered that OpenJDK incorrectly handled
CertificateVerify TLS handshake messages. A remote attacker could
possibly use this issue to insert, edit or obtain sensitive
information. This issue only affected OpenJDK 11. (CVE-2020-2655)

It was discovered that OpenJDK incorrectly enforced the limit of
datagram sockets that can be created by a code running within a Java
sandbox. An attacker could possibly use this issue to bypass the
sandbox restrictions causing a denial of service. This issue only
affected OpenJDK 8. (CVE-2020-2659).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4257-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");
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

if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk", pkgver:"8u242-b08-0ubuntu3~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre", pkgver:"8u242-b08-0ubuntu3~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u242-b08-0ubuntu3~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u242-b08-0ubuntu3~16.04")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u242-b08-0ubuntu3~16.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jdk", pkgver:"11.0.6+10-1ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre", pkgver:"11.0.6+10-1ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-headless", pkgver:"11.0.6+10-1ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-zero", pkgver:"11.0.6+10-1ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jdk", pkgver:"8u242-b08-0ubuntu3~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jre", pkgver:"8u242-b08-0ubuntu3~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u242-b08-0ubuntu3~18.04")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u242-b08-0ubuntu3~18.04")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jdk", pkgver:"11.0.6+10-1ubuntu1~19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jre", pkgver:"11.0.6+10-1ubuntu1~19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jre-headless", pkgver:"11.0.6+10-1ubuntu1~19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-11-jre-zero", pkgver:"11.0.6+10-1ubuntu1~19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jdk", pkgver:"8u242-b08-0ubuntu3~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jre", pkgver:"8u242-b08-0ubuntu3~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jre-headless", pkgver:"8u242-b08-0ubuntu3~19.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"openjdk-8-jre-zero", pkgver:"8u242-b08-0ubuntu3~19.10")) flag++;

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
