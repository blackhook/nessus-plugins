#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3268-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99686);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-10028", "CVE-2016-8667", "CVE-2016-9602", "CVE-2016-9603", "CVE-2016-9908", "CVE-2016-9912", "CVE-2016-9914", "CVE-2017-5552", "CVE-2017-5578", "CVE-2017-5987", "CVE-2017-6505");
  script_xref(name:"USN", value:"3268-1");

  script_name(english:"Ubuntu 17.04 : qemu vulnerabilities (USN-3268-1)");
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
"Zhenhao Hong discovered that QEMU incorrectly handled the Virtio GPU
device. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. (CVE-2016-10028)

It was discovered that QEMU incorrectly handled the JAZZ RC4030
device. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. (CVE-2016-8667)

Jann Horn discovered that QEMU incorrectly handled VirtFS directory
sharing. A privileged attacker inside the guest could use this issue
to access files on the host file system outside of the shared
directory and possibly escalate their privileges. In the default
installation, when QEMU is used with libvirt, attackers would be
isolated by the libvirt AppArmor profile. (CVE-2016-9602)

Gerd Hoffmann discovered that QEMU incorrectly handled the Cirrus VGA
device when being used with a VNC connection. A privileged attacker
inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly execute arbitrary code
on the host. In the default installation, when QEMU is used with
libvirt, attackers would be isolated by the libvirt AppArmor profile.
(CVE-2016-9603)

Li Qiang discovered that QEMU incorrectly handled the Virtio GPU
device. An attacker inside the guest could use this issue to cause
QEMU to leak contents of host memory. (CVE-2016-9908)

Li Qiang discovered that QEMU incorrectly handled the Virtio GPU
device. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service. (CVE-2016-9912,
CVE-2017-5552, CVE-2017-5578)

Li Qiang discovered that QEMU incorrectly handled VirtFS directory
sharing. A privileged attacker inside the guest could use this issue
to cause QEMU to crash, resulting in a denial of service.
(CVE-2016-9914)

Jiang Xin and Wjjzhang discovered that QEMU incorrectly handled SDHCI
device emulation. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2017-5987)

Li Qiang discovered that QEMU incorrectly handled USB OHCI controller
emulation. A privileged attacker inside the guest could use this issue
to cause QEMU to hang, resulting in a denial of service.
(CVE-2017-6505).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3268-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");
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
if (! preg(pattern:"^(17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"17.04", pkgname:"qemu-system", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-aarch64", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-arm", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-mips", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-misc", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-ppc", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-s390x", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-sparc", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"qemu-system-x86", pkgver:"1:2.8+dfsg-3ubuntu2.1")) flag++;

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
