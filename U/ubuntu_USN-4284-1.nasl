#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4284-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133797);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-14615", "CVE-2019-15099", "CVE-2019-15291", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18683", "CVE-2019-18786", "CVE-2019-18811", "CVE-2019-19050", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19071", "CVE-2019-19077", "CVE-2019-19078", "CVE-2019-19082", "CVE-2019-19241", "CVE-2019-19252", "CVE-2019-19332", "CVE-2019-19602", "CVE-2019-19767", "CVE-2019-19947", "CVE-2019-19965");
  script_xref(name:"USN", value:"4284-1");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 : Linux kernel vulnerabilities (USN-4284-1)");
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
"It was discovered that the Linux kernel did not properly clear data
structures on context switches for certain Intel graphics processors.
A local attacker could use this to expose sensitive information.
(CVE-2019-14615)

It was discovered that the Atheros 802.11ac wireless USB device driver
in the Linux kernel did not properly validate device metadata. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15099)

It was discovered that the HSA Linux kernel driver for AMD GPU devices
did not properly check for errors in certain situations, leading to a
NULL pointer dereference. A local attacker could possibly use this to
cause a denial of service. (CVE-2019-16229)

It was discovered that the Marvell 8xxx Libertas WLAN device driver in
the Linux kernel did not properly check for errors in certain
situations, leading to a NULL pointer dereference. A local attacker
could possibly use this to cause a denial of service. (CVE-2019-16232)

It was discovered that a race condition existed in the Virtual Video
Test Driver in the Linux kernel. An attacker with write access to
/dev/video0 on a system with the vivid module loaded could possibly
use this to gain administrative privileges. (CVE-2019-18683)

It was discovered that the Renesas Digital Radio Interface (DRIF)
driver in the Linux kernel did not properly initialize data. A local
attacker could possibly use this to expose sensitive information
(kernel memory). (CVE-2019-18786)

It was discovered that the Sound Open Firmware (SOF) driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-18811)

It was discovered that the crypto subsystem in the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19050, CVE-2019-19062)

It was discovered that multiple memory leaks existed in the Marvell
WiFi-Ex Driver for the Linux kernel. A local attacker could possibly
use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19057)

It was discovered that the Realtek rtlwifi USB device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19063)

It was discovered that the RSI 91x WLAN device driver in the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker could use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19071)

It was discovered that the Broadcom Netxtreme HCA device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19077)

It was discovered that the Atheros 802.11ac wireless USB device driver
in the Linux kernel did not properly deallocate memory in certain
error conditions. A local attacker could possibly use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-19078)

It was discovered that the AMD GPU device drivers in the Linux kernel
did not properly deallocate memory in certain error conditions. A
local attacker could use this to possibly cause a denial of service
(kernel memory exhaustion). (CVE-2019-19082)

It was discovered that the IO uring implementation in the Linux kernel
did not properly perform credentials checks in certain situations. A
local attacker could possibly use this to gain administrative
privileges. (CVE-2019-19241)

Or Cohen discovered that the virtual console subsystem in the Linux
kernel did not properly restrict writes to unimplemented vcsu
(unicode) devices. A local attacker could possibly use this to cause a
denial of service (system crash) or have other unspecified impacts.
(CVE-2019-19252)

It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle ioctl requests to get emulated CPUID
features. An attacker with access to /dev/kvm could use this to cause
a denial of service (system crash). (CVE-2019-19332)

It was discovered that a race condition existed in the Linux kernel on
x86 platforms when keeping track of which process was assigned control
of the FPU. A local attacker could use this to cause a denial of
service (memory corruption) or possibly gain administrative
privileges. (CVE-2019-19602)

It was discovered that the ext4 file system implementation in the
Linux kernel did not properly handle certain conditions. An attacker
could use this to specially craft an ext4 file system that, when
mounted, could cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-19767)

It was discovered that the Kvaser CAN/USB driver in the Linux kernel
did not properly initialize memory in certain situations. A local
attacker could possibly use this to expose sensitive information
(kernel memory). (CVE-2019-19947)

Gao Chuan discovered that the SAS Class driver in the Linux kernel
contained a race condition that could lead to a NULL pointer
dereference. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2019-19965)

It was discovered that the B2C2 FlexCop USB device driver in the Linux
kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2019-15291).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4284-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18683");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-14615", "CVE-2019-15099", "CVE-2019-15291", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18683", "CVE-2019-18786", "CVE-2019-18811", "CVE-2019-19050", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19071", "CVE-2019-19077", "CVE-2019-19078", "CVE-2019-19082", "CVE-2019-19241", "CVE-2019-19252", "CVE-2019-19332", "CVE-2019-19602", "CVE-2019-19767", "CVE-2019-19947", "CVE-2019-19965");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4284-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1012-gcp", pkgver:"5.3.0-1012.13~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1013-azure", pkgver:"5.3.0-1013.14~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1018-raspi2", pkgver:"5.3.0-1018.20~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-40-generic", pkgver:"5.3.0-40.32~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-40-generic-lpae", pkgver:"5.3.0-40.32~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-40-lowlatency", pkgver:"5.3.0-40.32~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure-edge", pkgver:"5.3.0.1013.13")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp-edge", pkgver:"5.3.0.1012.11")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"5.3.0.40.97")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"5.3.0.40.97")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"5.3.0.40.97")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2-hwe-18.04", pkgver:"5.3.0.1018.7")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"5.3.0.40.97")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"5.3.0.40.97")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1009-oracle", pkgver:"5.3.0-1009.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1010-kvm", pkgver:"5.3.0-1010.11")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1011-aws", pkgver:"5.3.0-1011.12")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1012-gcp", pkgver:"5.3.0-1012.13")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1013-azure", pkgver:"5.3.0-1013.14")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1018-raspi2", pkgver:"5.3.0-1018.20")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-40-generic", pkgver:"5.3.0-40.32")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-40-generic-lpae", pkgver:"5.3.0-40.32")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-40-lowlatency", pkgver:"5.3.0-40.32")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-40-snapdragon", pkgver:"5.3.0-40.32")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-aws", pkgver:"5.3.0.1011.13")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-azure", pkgver:"5.3.0.1013.31")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gcp", pkgver:"5.3.0.1012.13")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic", pkgver:"5.3.0.40.34")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic-lpae", pkgver:"5.3.0.40.34")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gke", pkgver:"5.3.0.1012.13")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-kvm", pkgver:"5.3.0.1010.12")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-lowlatency", pkgver:"5.3.0.40.34")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-oracle", pkgver:"5.3.0.1009.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-raspi2", pkgver:"5.3.0.1018.15")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-snapdragon", pkgver:"5.3.0.40.34")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-virtual", pkgver:"5.3.0.40.34")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.3-aws / linux-image-5.3-azure / linux-image-5.3-gcp / etc");
}
