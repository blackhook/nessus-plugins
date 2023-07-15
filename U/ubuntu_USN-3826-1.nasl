#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3826-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119216);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-10839", "CVE-2018-11806", "CVE-2018-12617", "CVE-2018-16847", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18849", "CVE-2018-18954", "CVE-2018-19364");
  script_xref(name:"USN", value:"3826-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 18.10 : QEMU vulnerabilities (USN-3826-1)");
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
"Daniel Shapira and Arash Tohidi discovered that QEMU incorrectly
handled NE2000 device emulation. An attacker inside the guest could
use this issue to cause QEMU to crash, resulting in a denial of
service. (CVE-2018-10839)

It was discovered that QEMU incorrectly handled the Slirp networking
back-end. A privileged attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service, or possibly
execute arbitrary code on the host. In the default installation, when
QEMU is used with libvirt, attackers would be isolated by the libvirt
AppArmor profile. This issue only affected Ubuntu 14.04 LTS, Ubuntu
16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-11806)

Fakhri Zulkifli discovered that the QEMU guest agent incorrectly
handled certain QMP commands. An attacker could possibly use this
issue to crash the QEMU guest agent, resulting in a denial of service.
(CVE-2018-12617)

Li Qiang discovered that QEMU incorrectly handled NVM Express
Controller emulation. An attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service, or
possibly execute arbitrary code on the host. In the default
installation, when QEMU is used with libvirt, attackers would be
isolated by the libvirt AppArmor profile. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-16847)

Daniel Shapira and Arash Tohidi discovered that QEMU incorrectly
handled RTL8139 device emulation. An attacker inside the guest could
use this issue to cause QEMU to crash, resulting in a denial of
service. (CVE-2018-17958)

Daniel Shapira and Arash Tohidi discovered that QEMU incorrectly
handled PCNET device emulation. An attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2018-17962)

Daniel Shapira discovered that QEMU incorrectly handled large packet
sizes. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. (CVE-2018-17963)

It was discovered that QEMU incorrectly handled LSI53C895A device
emulation. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. (CVE-2018-18849)

Moguofang discovered that QEMU incorrectly handled the IPowerNV LPC
controller. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-18954)

Zhibin Hu discovered that QEMU incorrectly handled the Plan 9 File
System support. An attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service.
(CVE-2018-19364).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3826-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");
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

if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.44")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-arm", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-mips", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-misc", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-ppc", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-s390x", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-sparc", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.33")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-arm", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-mips", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-misc", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-ppc", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-s390x", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-sparc", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"qemu-system-x86", pkgver:"1:2.11+dfsg-1ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-arm", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-mips", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-misc", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-ppc", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-s390x", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-sparc", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"qemu-system-x86", pkgver:"1:2.12+dfsg-3ubuntu8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-system / qemu-system-aarch64 / qemu-system-arm / etc");
}
