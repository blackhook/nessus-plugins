#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3575-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106927);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-11334", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15118", "CVE-2017-15119", "CVE-2017-15124", "CVE-2017-15268", "CVE-2017-15289", "CVE-2017-16845", "CVE-2017-17381", "CVE-2017-18043", "CVE-2018-5683");
  script_xref(name:"USN", value:"3575-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 : qemu vulnerabilities (USN-3575-1)");
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
"It was discovered that QEMU incorrectly handled guest ram. A
privileged attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-11334)

David Buchanan discovered that QEMU incorrectly handled the VGA
device. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. This issue was
only addressed in Ubuntu 17.10. (CVE-2017-13672)

Thomas Garnier discovered that QEMU incorrectly handled multiboot. An
attacker could use this issue to cause QEMU to crash, resulting in a
denial of service, or possibly execute arbitrary code on the host. In
the default installation, when QEMU is used with libvirt, attackers
would be isolated by the libvirt AppArmor profile. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-14167)

Tuomas Tynkkynen discovered that QEMU incorrectly handled VirtFS
directory sharing. An attacker could use this issue to obtain
sensitive information from host memory. (CVE-2017-15038)

Eric Blake discovered that QEMU incorrectly handled memory in the NBD
server. An attacker could use this issue to cause the NBD server to
crash, resulting in a denial of service. This issue only affected
Ubuntu 17.10. (CVE-2017-15118)

Eric Blake discovered that QEMU incorrectly handled certain options to
the NBD server. An attacker could use this issue to cause the NBD
server to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-15119)

Daniel Berrange discovered that QEMU incorrectly handled the VNC
server. A remote attacker could possibly use this issue to consume
memory, resulting in a denial of service. This issue was only
addressed in Ubuntu 17.10. (CVE-2017-15124)

Carl Brassey discovered that QEMU incorrectly handled certain
websockets. A remote attacker could possibly use this issue to consume
memory, resulting in a denial of service. This issue only affected
Ubuntu 17.10. (CVE-2017-15268)

Guoxiang Niu discovered that QEMU incorrectly handled the Cirrus VGA
device. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service.
(CVE-2017-15289)

Cyrille Chatras discovered that QEMU incorrectly handled certain PS2
values during migration. An attacker could possibly use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 17.10. (CVE-2017-16845)

It was discovered that QEMU incorrectly handled the Virtio Vring
implementation. An attacker could possibly use this issue to cause
QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2017-17381)

Eric Blake discovered that QEMU incorrectly handled certain rounding
operations. An attacker could possibly use this issue to cause QEMU to
crash, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-18043)

Jiang Xin and Lin ZheCheng discovered that QEMU incorrectly handled
the VGA device. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2018-5683).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3575-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/02");
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

if (ubuntu_check(osver:"14.04", pkgname:"qemu-system", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-aarch64", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-arm", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-mips", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-misc", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-ppc", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-sparc", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"qemu-system-x86", pkgver:"2.0.0+dfsg-2ubuntu1.39")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-arm", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-mips", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-misc", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-ppc", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-s390x", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-sparc", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"qemu-system-x86", pkgver:"1:2.5+dfsg-5ubuntu10.22")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-aarch64", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-arm", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-mips", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-misc", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-ppc", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-s390x", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-sparc", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"qemu-system-x86", pkgver:"1:2.10+dfsg-0ubuntu3.5")) flag++;

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
