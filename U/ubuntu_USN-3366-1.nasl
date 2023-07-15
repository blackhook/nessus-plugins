#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3366-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102014);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243");
  script_xref(name:"USN", value:"3366-1");

  script_name(english:"Ubuntu 16.04 LTS / 17.04 : openjdk-8 vulnerabilities (USN-3366-1)");
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
"It was discovered that the JPEGImageReader class in OpenJDK would
incorrectly read unused image data. An attacker could use this to
specially construct a jpeg image file that when opened by a Java
application would cause a denial of service. (CVE-2017-10053)

It was discovered that the JAR verifier in OpenJDK did not properly
handle archives containing files missing digests. An attacker could
use this to modify the signed contents of a JAR file. (CVE-2017-10067)

It was discovered that integer overflows existed in the Hotspot
component of OpenJDK when generating range check loop predicates. An
attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions and cause
a denial of service or possibly execute arbitrary code.
(CVE-2017-10074)

It was discovered that the JavaScript Scripting component of OpenJDK
incorrectly allowed access to Java APIs. An attacker could use this to
specially craft JavaScript code to bypass access restrictions.
(CVE-2017-10078)

It was discovered that OpenJDK did not properly process parentheses in
function signatures. An attacker could use this to specially construct
an untrusted Java application or applet that could escape sandbox
restrictions. (CVE-2017-10081)

It was discovered that the ThreadPoolExecutor class in OpenJDK did not
properly perform access control checks when cleaning up threads. An
attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions and
possibly execute arbitrary code. (CVE-2017-10087)

It was discovered that the ServiceRegistry implementation in OpenJDK
did not perform access control checks in certain situations. An
attacker could use this to specially construct an untrusted Java
application or applet that escaped sandbox restrictions.
(CVE-2017-10089)

It was discovered that the channel groups implementation in OpenJDK
did not properly perform access control checks in some situations. An
attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions.
(CVE-2017-10090)

It was discovered that the DTM exception handling code in the JAXP
component of OpenJDK did not properly perform access control checks.
An attacker could use this to specially construct an untrusted Java
application or applet that could escape sandbox restrictions.
(CVE-2017-10096)

It was discovered that the JAXP component of OpenJDK incorrectly
granted access to some internal resolvers. An attacker could use this
to specially construct an untrusted Java application or applet that
could escape sandbox restrictions. (CVE-2017-10101)

It was discovered that the Distributed Garbage Collector (DGC) in
OpenJDK did not properly track references in some situations. A remote
attacker could possibly use this to execute arbitrary code.
(CVE-2017-10102)

It was discovered that the Activation ID implementation in the RMI
component of OpenJDK did not properly check access control permissions
in some situations. An attacker could use this to specially construct
an untrusted Java application or applet that could escape sandbox
restrictions. (CVE-2017-10107)

It was discovered that the BasicAttribute class in OpenJDK did not
properly bound memory allocation when de-serializing objects. An
attacker could use this to cause a denial of service (memory
consumption). (CVE-2017-10108)

It was discovered that the CodeSource class in OpenJDK did not
properly bound memory allocations when de-serializing object
instances. An attacker could use this to cause a denial of service
(memory consumption). (CVE-2017-10109)

It was discovered that the AWT ImageWatched class in OpenJDK did not
properly perform access control checks, An attacker could use this to
specially construct an untrusted Java application or applet that could
escape sandbox restrictions (CVE-2017-10110)

Jackson Davis discovered that the LambdaFormEditor class in the
Libraries component of OpenJDK did not correctly perform bounds checks
in the permuteArgumentsForm() function. An attacker could use this to
specially construct an untrusted Java application or applet that could
escape sandbox restrictions and possibly execute arbitrary code.
(CVE-2017-10111)

It was discovered that a timing side-channel vulnerability existed in
the DSA implementation in OpenJDK. An attacker could use this to
expose sensitive information. (CVE-2017-10115)

It was discovered that the LDAP implementation in OpenJDK incorrectly
followed references to non-LDAP URLs. An attacker could use this to
specially craft an LDAP referral URL that exposes sensitive
information or bypass access restrictions. (CVE-2017-10116)

It was discovered that a timing side-channel vulnerability existed in
the ECDSA implementation in OpenJDK. An attacker could use this to
expose sensitive information. (CVE-2017-10118)

Ilya Maykov discovered that a timing side-channel vulnerability
existed in the PKCS#8 implementation in OpenJDK. An attacker could use
this to expose sensitive information. (CVE-2017-10135)

It was discovered that the Elliptic Curve (EC) implementation in
OpenJDK did not properly compute certain elliptic curve points. An
attacker could use this to expose sensitive information.
(CVE-2017-10176)

It was discovered that OpenJDK did not properly restrict weak key
sizes in some situations. An attacker could use this to specially
construct an untrusted Java application or applet that could escape
sandbox restrictions. (CVE-2017-10193)

It was discovered that OpenJDK did not properly enforce disabled
algorithm restrictions on X.509 certificate chains. An attacker could
use this to expose sensitive information or escape sandbox
restrictions. (CVE-2017-10198)

It was discovered that OpenJDK did not properly perform access control
checks when handling Web Service Definition Language (WSDL) XML
documents. An attacker could use this to expose sensitive information.
(CVE-2017-10243).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3366-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk", pkgver:"8u131-b11-2ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jdk-headless", pkgver:"8u131-b11-2ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre", pkgver:"8u131-b11-2ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u131-b11-2ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-jamvm", pkgver:"8u131-b11-2ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u131-b11-2ubuntu1.16.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jdk", pkgver:"8u131-b11-2ubuntu1.17.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jdk-headless", pkgver:"8u131-b11-2ubuntu1.17.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jre", pkgver:"8u131-b11-2ubuntu1.17.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jre-headless", pkgver:"8u131-b11-2ubuntu1.17.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openjdk-8-jre-zero", pkgver:"8u131-b11-2ubuntu1.17.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjdk-8-jdk / openjdk-8-jdk-headless / openjdk-8-jre / etc");
}
