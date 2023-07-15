#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3339-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101024);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-6329", "CVE-2017-7479", "CVE-2017-7508", "CVE-2017-7512", "CVE-2017-7520", "CVE-2017-7521");
  script_xref(name:"USN", value:"3339-1");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : openvpn vulnerabilities (USN-3339-1) (SWEET32)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Karthikeyan Bhargavan and Gaetan Leurent discovered that 64-bit block
ciphers are vulnerable to a birthday attack. A remote attacker could
possibly use this issue to recover cleartext data. Fixing this issue
requires a configuration change to switch to a different cipher. This
update adds a warning to the log file when a 64-bit block cipher is in
use. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and
Ubuntu 16.10. (CVE-2016-6329)

It was discovered that OpenVPN incorrectly handled rollover of packet
ids. An authenticated remote attacker could use this issue to cause
OpenVPN to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2017-7479)

Guido Vranken discovered that OpenVPN incorrectly handled certain
malformed IPv6 packets. A remote attacker could use this issue to
cause OpenVPN to crash, resulting in a denial of service.
(CVE-2017-7508)

Guido Vranken discovered that OpenVPN incorrectly handled memory. A
remote attacker could use this issue to cause OpenVPN to crash,
resulting in a denial of service. (CVE-2017-7512)

Guido Vranken discovered that OpenVPN incorrectly handled an HTTP
proxy with NTLM authentication. A remote attacker could use this issue
to cause OpenVPN clients to crash, resulting in a denial of service,
or possibly expose sensitive memory contents. (CVE-2017-7520)

Guido Vranken discovered that OpenVPN incorrectly handled certain x509
extensions. A remote attacker could use this issue to cause OpenVPN to
crash, resulting in a denial of service. (CVE-2017-7521).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3339-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openvpn package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^(14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"openvpn", pkgver:"2.3.2-7ubuntu3.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"openvpn", pkgver:"2.3.10-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"openvpn", pkgver:"2.3.11-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"openvpn", pkgver:"2.4.0-4ubuntu1.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn");
}
