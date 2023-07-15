#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3497-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104846);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");
  script_xref(name:"USN", value:"3497-1");

  script_name(english:"Ubuntu 14.04 LTS : openjdk-7 vulnerabilities (USN-3497-1)");
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
"It was discovered that the Smart Card IO subsystem in OpenJDK did not
properly maintain state. An attacker could use this to specially
construct an untrusted Java application or applet to gain access to a
smart card, bypassing sandbox restrictions. (CVE-2017-10274)

Gaston Traberg discovered that the Serialization component of OpenJDK
did not properly limit the amount of memory allocated when performing
deserializations. An attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2017-10281)

It was discovered that the Remote Method Invocation (RMI) component in
OpenJDK did not properly handle unreferenced objects. An attacker
could use this to specially construct an untrusted Java application or
applet that could escape sandbox restrictions. (CVE-2017-10285)

It was discovered that the HTTPUrlConnection classes in OpenJDK did
not properly handle newlines. An attacker could use this to convince a
Java application or applet to inject headers into http requests.
(CVE-2017-10295)

Francesco Palmarini, Marco Squarcina, Mauro Tempesta, and Riccardo
Focardi discovered that the Serialization component of OpenJDK did not
properly restrict the amount of memory allocated when deserializing
objects from Java Cryptography Extension KeyStore (JCEKS). An attacker
could use this to cause a denial of service (memory exhaustion).
(CVE-2017-10345)

It was discovered that the Hotspot component of OpenJDK did not
properly perform loader checks when handling the invokespecial JVM
instruction. An attacker could use this to specially construct an
untrusted Java application or applet that could escape sandbox
restrictions. (CVE-2017-10346)

Gaston Traberg discovered that the Serialization component of OpenJDK
did not properly limit the amount of memory allocated when performing
deserializations in the SimpleTimeZone class. An attacker could use
this to cause a denial of service (memory exhaustion).
(CVE-2017-10347)

It was discovered that the Serialization component of OpenJDK did not
properly limit the amount of memory allocated when performing
deserializations. An attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2017-10348, CVE-2017-10357)

It was discovered that the JAXP component in OpenJDK did not properly
limit the amount of memory allocated when performing deserializations.
An attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2017-10349)

It was discovered that the JAX-WS component in OpenJDK did not
properly limit the amount of memory allocated when performing
deserializations. An attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2017-10350)

It was discovered that the Networking component of OpenJDK did not
properly set timeouts on FTP client actions. A remote attacker could
use this to cause a denial of service (application hang).
(CVE-2017-10355)

Francesco Palmarini, Marco Squarcina, Mauro Tempesta, Riccardo
Focardi, and Tobias Ospelt discovered that the Security component in
OpenJDK did not sufficiently protect password-based encryption keys in
key stores. An attacker could use this to expose sensitive
information. (CVE-2017-10356)

Jeffrey Altman discovered that the Kerberos client implementation in
OpenJDK incorrectly trusted unauthenticated portions of Kerberos
tickets. A remote attacker could use this to impersonate trusted
network services or perform other attacks. (CVE-2017-10388).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3497-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/29");
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
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"icedtea-7-jre-jamvm", pkgver:"7u151-2.6.11-2ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre", pkgver:"7u151-2.6.11-2ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-headless", pkgver:"7u151-2.6.11-2ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-lib", pkgver:"7u151-2.6.11-2ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-zero", pkgver:"7u151-2.6.11-2ubuntu0.14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-7-jre-jamvm / openjdk-7-jre / openjdk-7-jre-headless / etc");
}
