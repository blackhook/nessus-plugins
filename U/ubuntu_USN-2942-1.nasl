#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2942-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90245);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-0636");
  script_xref(name:"USN", value:"2942-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.10 : openjdk-7 vulnerability (USN-2942-1)");
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
"A vulnerability was discovered in the JRE related to information
disclosure, data integrity, and availability. An attacker could
exploit these to cause a denial of service, expose sensitive data over
the network, or possibly execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2942-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/28");
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
if (! preg(pattern:"^(14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"icedtea-7-jre-jamvm", pkgver:"7u95-2.6.4-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jdk", pkgver:"7u95-2.6.4-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre", pkgver:"7u95-2.6.4-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-headless", pkgver:"7u95-2.6.4-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-lib", pkgver:"7u95-2.6.4-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"openjdk-7-jre-zero", pkgver:"7u95-2.6.4-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"icedtea-7-jre-jamvm", pkgver:"7u95-2.6.4-0ubuntu0.15.10.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"openjdk-7-jre", pkgver:"7u95-2.6.4-0ubuntu0.15.10.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"openjdk-7-jre-headless", pkgver:"7u95-2.6.4-0ubuntu0.15.10.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"openjdk-7-jre-lib", pkgver:"7u95-2.6.4-0ubuntu0.15.10.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"openjdk-7-jre-zero", pkgver:"7u95-2.6.4-0ubuntu0.15.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-7-jre-jamvm / openjdk-7-jdk / openjdk-7-jre / etc");
}
