#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3840-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119497);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-0734", "CVE-2018-0735", "CVE-2018-5407");
  script_xref(name:"USN", value:"3840-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 18.10 : openssl, openssl1.0 vulnerabilities (USN-3840-1)");
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
"Samuel Weiser discovered that OpenSSL incorrectly handled DSA signing.
An attacker could possibly use this issue to perform a timing
side-channel attack and recover private DSA keys. (CVE-2018-0734)

Samuel Weiser discovered that OpenSSL incorrectly handled ECDSA
signing. An attacker could possibly use this issue to perform a timing
side-channel attack and recover private ECDSA keys. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-0735)

Billy Bob Brumley, Cesar Pereida Garcia, Sohaib ul Hassan, Nicola
Tuveri, and Alejandro Cabrera Aldaya discovered that Simultaneous
Multithreading (SMT) architectures are vulnerable to side-channel
leakage. This issue is known as 'PortSmash'. An attacker could
possibly use this issue to perform a timing side-channel attack and
recover private keys. (CVE-2018-5407).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3840-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libssl1.0.0 and / or libssl1.1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/07");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04|18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04 / 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu2.27")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libssl1.0.0", pkgver:"1.0.2g-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libssl1.0.0", pkgver:"1.0.2n-1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libssl1.1", pkgver:"1.1.0g-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libssl1.0.0", pkgver:"1.0.2n-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libssl1.1", pkgver:"1.1.1-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl1.0.0 / libssl1.1");
}
