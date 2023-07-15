#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4433-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138998);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-14556", "CVE-2020-14562", "CVE-2020-14573", "CVE-2020-14577", "CVE-2020-14581", "CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621");
  script_xref(name:"USN", value:"4433-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 : OpenJDK vulnerabilities (USN-4433-1)");
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
"Johannes Kuhn discovered that OpenJDK incorrectly handled access
control contexts. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2020-14556) It was discovered that OpenJDK
incorrectly handled memory allocation when reading TIFF image files.
An attacker could possibly use this issue to cause a denial of
service. (CVE-2020-14562) It was discovered that OpenJDK incorrectly
handled input data. An attacker could possibly use this issue to
insert, edit or obtain sensitive information. (CVE-2020-14573)
Philippe Arteau discovered that OpenJDK incorrectly verified names in
TLS server's X.509 certificates. An attacker could possibly use this
issue to obtain sensitive information. (CVE-2020-14577) It was
discovered that OpenJDK incorrectly handled image files. An attacker
could possibly use this issue to obtain sensitive information.
(CVE-2020-14581) Markus Loewe discovered that OpenJDK incorrectly
handled concurrent access in java.nio.Buffer class. An attacker could
use this issue to bypass the sandbox restrictions and cause
unspecified impact. (CVE-2020-14583) It was discovered that OpenJDK
incorrectly handled transformation of images. An attacker could
possibly use this issue to bypass sandbox restrictions and insert,
edit or obtain sensitive information. (CVE-2020-14593) Roman Shemyakin
discovered that OpenJDK incorrectly handled XML files. An attacker
could possibly use this issue to insert, edit or obtain sensitive
information. (CVE-2020-14621).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4433-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14556");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jdk", pkgver:"11.0.8+10-0ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre", pkgver:"11.0.8+10-0ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-headless", pkgver:"11.0.8+10-0ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-zero", pkgver:"11.0.8+10-0ubuntu1~18.04.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"openjdk-11-jdk", pkgver:"11.0.8+10-0ubuntu1~20.04")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"openjdk-11-jre", pkgver:"11.0.8+10-0ubuntu1~20.04")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"openjdk-11-jre-headless", pkgver:"11.0.8+10-0ubuntu1~20.04")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"openjdk-11-jre-zero", pkgver:"11.0.8+10-0ubuntu1~20.04")) flag++;

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
