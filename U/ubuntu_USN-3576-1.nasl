#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3576-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106928);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2016-5008", "CVE-2017-1000256", "CVE-2018-5748", "CVE-2018-6764");
  script_xref(name:"USN", value:"3576-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : libvirt vulnerabilities (USN-3576-1)");
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
"Vivian Zhang and Christoph Anton Mitterer discovered that libvirt
incorrectly disabled password authentication when the VNC password was
set to an empty string. A remote attacker could possibly use this
issue to bypass authentication, contrary to expectations. This issue
only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-5008)

Daniel P. Berrange discovered that libvirt incorrectly handled
validating SSL/TLS certificates. A remote attacker could possibly use
this issue to obtain sensitive information. This issue only affected
Ubuntu 17.10. (CVE-2017-1000256)

Daniel P. Berrange and Peter Krempa discovered that libvirt
incorrectly handled large QEMU replies. An attacker could possibly use
this issue to cause libvirt to crash, resulting in a denial of
service. (CVE-2018-5748)

Pedro Sampaio discovered that libvirt incorrectly handled the
libnss_dns.so module. An attacker in a libvirt_lxc session could
possibly use this issue to execute arbitrary code. This issue only
affected Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-6764).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3576-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libvirt-bin and / or libvirt0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/21");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libvirt-bin", pkgver:"1.2.2-0ubuntu13.1.26")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libvirt0", pkgver:"1.2.2-0ubuntu13.1.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libvirt-bin", pkgver:"1.3.1-1ubuntu10.19")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libvirt0", pkgver:"1.3.1-1ubuntu10.19")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libvirt-bin", pkgver:"3.6.0-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libvirt0", pkgver:"3.6.0-1ubuntu6.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt-bin / libvirt0");
}
