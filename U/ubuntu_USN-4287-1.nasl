#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4287-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133800);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-14615", "CVE-2019-15099", "CVE-2019-15291", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18683", "CVE-2019-18786", "CVE-2019-18809", "CVE-2019-18885", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19071", "CVE-2019-19078", "CVE-2019-19082", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19767", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108", "CVE-2020-7053");
  script_xref(name:"USN", value:"4287-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-4287-1)");
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

It was discovered that the Afatech AF9005 DVB-T USB device driver in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-18809)

It was discovered that the btrfs file system in the Linux kernel did
not properly validate metadata, leading to a NULL pointer dereference.
An attacker could use this to specially craft a file system image
that, when mounted, could cause a denial of service (system crash).
(CVE-2019-18885)

It was discovered that multiple memory leaks existed in the Marvell
WiFi-Ex Driver for the Linux kernel. A local attacker could possibly
use this to cause a denial of service (kernel memory exhaustion).
(CVE-2019-19057)

It was discovered that the crypto subsystem in the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (kernel memory
exhaustion). (CVE-2019-19062)

It was discovered that the Realtek rtlwifi USB device driver in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could possibly use this to cause a denial
of service (kernel memory exhaustion). (CVE-2019-19063)

It was discovered that the RSI 91x WLAN device driver in the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker could use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19071)

It was discovered that the Atheros 802.11ac wireless USB device driver
in the Linux kernel did not properly deallocate memory in certain
error conditions. A local attacker could possibly use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-19078)

It was discovered that the AMD GPU device drivers in the Linux kernel
did not properly deallocate memory in certain error conditions. A
local attacker could use this to possibly cause a denial of service
(kernel memory exhaustion). (CVE-2019-19082)

Dan Carpenter discovered that the AppleTalk networking subsystem of
the Linux kernel did not properly handle certain error conditions,
leading to a NULL pointer dereference. A local attacker could use this
to cause a denial of service (system crash). (CVE-2019-19227)

It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle ioctl requests to get emulated CPUID
features. An attacker with access to /dev/kvm could use this to cause
a denial of service (system crash). (CVE-2019-19332)

It was discovered that the ext4 file system implementation in the
Linux kernel did not properly handle certain conditions. An attacker
could use this to specially craft an ext4 file system that, when
mounted, could cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-19767)

Gao Chuan discovered that the SAS Class driver in the Linux kernel
contained a race condition that could lead to a NULL pointer
dereference. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2019-19965)

It was discovered that the Datagram Congestion Control Protocol (DCCP)
implementation in the Linux kernel did not properly deallocate memory
in certain error conditions. An attacker could possibly use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-20096)

Mitchell Frank discovered that the Wi-Fi implementation in the Linux
kernel when used as an access point would send IAPP location updates
for stations before client authentication had completed. A physically
proximate attacker could use this to cause a denial of service.
(CVE-2019-5108)

It was discovered that a race condition can lead to a use-after-free
while destroying GEM contexts in the i915 driver for the Linux kernel.
A local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2020-7053)

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
    value:"https://usn.ubuntu.com/4287-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18683");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-4.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
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
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-14615", "CVE-2019-15099", "CVE-2019-15291", "CVE-2019-16229", "CVE-2019-16232", "CVE-2019-18683", "CVE-2019-18786", "CVE-2019-18809", "CVE-2019-18885", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19071", "CVE-2019-19078", "CVE-2019-19082", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19767", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-5108", "CVE-2020-7053");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4287-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1033-oracle", pkgver:"4.15.0-1033.36~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1055-gcp", pkgver:"4.15.0-1055.59")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1060-aws", pkgver:"4.15.0-1060.62~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-1071-azure", pkgver:"4.15.0-1071.76")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-88-generic", pkgver:"4.15.0-88.88~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-88-generic-lpae", pkgver:"4.15.0-88.88~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.15.0-88-lowlatency", pkgver:"4.15.0-88.88~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws-hwe", pkgver:"4.15.0.1060.60")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-azure", pkgver:"4.15.0.1071.74")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gcp", pkgver:"4.15.0.1055.69")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.15.0.88.98")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae-hwe-16.04", pkgver:"4.15.0.88.98")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1055.69")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.15.0.88.98")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oem", pkgver:"4.15.0.88.98")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-oracle", pkgver:"4.15.0.1033.26")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual-hwe-16.04", pkgver:"4.15.0.88.98")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1033-oracle", pkgver:"4.15.0-1033.36")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1052-gke", pkgver:"4.15.0-1052.55")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1053-kvm", pkgver:"4.15.0-1053.53")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1055-raspi2", pkgver:"4.15.0-1055.59")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1060-aws", pkgver:"4.15.0-1060.62")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1072-snapdragon", pkgver:"4.15.0-1072.79")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-88-generic", pkgver:"4.15.0-88.88")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-88-generic-lpae", pkgver:"4.15.0-88.88")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-88-lowlatency", pkgver:"4.15.0-88.88")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws", pkgver:"4.15.0.1060.61")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws-lts-18.04", pkgver:"4.15.0.1060.61")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic", pkgver:"4.15.0.88.80")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae", pkgver:"4.15.0.88.80")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1052.56")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-4.15", pkgver:"4.15.0.1052.56")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-kvm", pkgver:"4.15.0.1053.53")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency", pkgver:"4.15.0.88.80")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle", pkgver:"4.15.0.1033.38")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle-lts-18.04", pkgver:"4.15.0.1033.38")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2", pkgver:"4.15.0.1055.53")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon", pkgver:"4.15.0.1072.75")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual", pkgver:"4.15.0.88.80")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.15-aws / linux-image-4.15-azure / etc");
}
