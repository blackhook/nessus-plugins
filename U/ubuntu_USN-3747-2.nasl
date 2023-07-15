#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3747-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117479);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-2825", "CVE-2018-2826", "CVE-2018-2952", "CVE-2018-2972");
  script_xref(name:"USN", value:"3747-2");

  script_name(english:"Ubuntu 18.04 LTS : OpenJDK 10 regression (USN-3747-2)");
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
"USN-3747-1 fixed vulnerabilities in OpenJDK 10 for Ubuntu 18.04 LTS.
Unfortunately, that update introduced a regression around
accessability support that prevented some Java applications from
starting. This update fixes the problem.

We apologize for the inconvenience.

It was discovered that OpenJDK did not properly validate types in some
situations. An attacker could use this to construct a Java class that
could possibly bypass sandbox restrictions. (CVE-2018-2825,
CVE-2018-2826)

It was discovered that the PatternSyntaxException class in OpenJDK did
not properly validate arguments passed to it. An attacker could use
this to potentially construct a class that caused a denial of service
(excessive memory consumption). (CVE-2018-2952)

Daniel Bleichenbacher discovered a vulnerability in the Galois/Counter
Mode (GCM) mode of operation for symmetric block ciphers in OpenJDK.
An attacker could use this to expose sensitive information.
(CVE-2018-2972).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3747-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jdk", pkgver:"10.0.2+13-1ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jdk-headless", pkgver:"10.0.2+13-1ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre", pkgver:"10.0.2+13-1ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-headless", pkgver:"10.0.2+13-1ubuntu0.18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"openjdk-11-jre-zero", pkgver:"10.0.2+13-1ubuntu0.18.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjdk-11-jdk / openjdk-11-jdk-headless / openjdk-11-jre / etc");
}
