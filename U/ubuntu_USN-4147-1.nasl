#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4147-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129677);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-0136", "CVE-2019-10207", "CVE-2019-13631", "CVE-2019-15090", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15223", "CVE-2019-15538", "CVE-2019-15925", "CVE-2019-15926", "CVE-2019-9506");
  script_xref(name:"USN", value:"4147-1");

  script_name(english:"Ubuntu 18.04 LTS / 19.04 : linux, linux-aws, linux-azure, linux-gcp, linux-gke-5.0, linux-hwe, (USN-4147-1)");
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
"It was discovered that the Intel Wi-Fi device driver in the Linux
kernel did not properly validate certain Tunneled Direct Link Setup
(TDLS). A physically proximate attacker could use this to cause a
denial of service (Wi-Fi disconnect). (CVE-2019-0136)

It was discovered that the Bluetooth UART implementation in the Linux
kernel did not properly check for missing tty operations. A local
attacker could use this to cause a denial of service. (CVE-2019-10207)

It was discovered that the GTCO tablet input driver in the Linux
kernel did not properly bounds check the initial HID report sent by
the device. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2019-13631)

It was discovered that an out-of-bounds read existed in the QLogic
QEDI iSCSI Initiator Driver in the Linux kernel. A local attacker
could possibly use this to expose sensitive information (kernel
memory). (CVE-2019-15090)

Hui Peng and Mathias Payer discovered that the USB audio driver for
the Linux kernel did not properly validate device meta data. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15117)

Hui Peng and Mathias Payer discovered that the USB audio driver for
the Linux kernel improperly performed recursion while handling device
meta data. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2019-15118)

It was discovered that the Raremono AM/FM/SW radio device driver in
the Linux kernel did not properly allocate memory, leading to a
use-after-free. A physically proximate attacker could use this to
cause a denial of service or possibly execute arbitrary code.
(CVE-2019-15211)

It was discovered at a double-free error existed in the USB Rio 500
device driver for the Linux kernel. A physically proximate attacker
could use this to cause a denial of service. (CVE-2019-15212)

It was discovered that a race condition existed in the CPiA2
video4linux device driver for the Linux kernel, leading to a
use-after-free. A physically proximate attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15215)

It was discovered that a race condition existed in the Softmac USB
Prism54 device driver in the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2019-15220)

Benjamin Moody discovered that the XFS file system in the Linux kernel
did not properly handle an error condition when out of disk quota. A
local attacker could possibly use this to cause a denial of service.
(CVE-2019-15538)

It was discovered that the Hisilicon HNS3 ethernet device driver in
the Linux kernel contained an out of bounds access vulnerability. A
local attacker could use this to possibly cause a denial of service
(system crash). (CVE-2019-15925)

It was discovered that the Atheros mobile chipset driver in the Linux
kernel did not properly validate data in some situations. An attacker
could use this to cause a denial of service (system crash).
(CVE-2019-15926)

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper B. Rasmussen
discovered that the Bluetooth protocol BR/EDR specification did not
properly require sufficiently strong encryption key lengths. A
physically proximate attacker could use this to expose sensitive
information. (CVE-2019-9506)

It was discovered that ZR364XX Camera USB device driver for the Linux
kernel did not properly initialize memory. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2019-15217)

It was discovered that the Siano USB MDTV receiver device driver in
the Linux kernel made improper assumptions about the device
characteristics. A physically proximate attacker could use this cause
a denial of service (system crash). (CVE-2019-15218)

It was discovered that the Line 6 POD USB device driver in the Linux
kernel did not properly validate data size information from the
device. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2019-15221)

It was discovered that the Line 6 USB driver for the Linux kernel
contained a race condition when the device was disconnected. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15223).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4147-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(18\.04|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-0136", "CVE-2019-10207", "CVE-2019-13631", "CVE-2019-15090", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15223", "CVE-2019-15538", "CVE-2019-15925", "CVE-2019-15926", "CVE-2019-9506");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4147-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1020-gke", pkgver:"5.0.0-1020.20~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-31-generic", pkgver:"5.0.0-31.33~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-31-generic-lpae", pkgver:"5.0.0-31.33~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-31-lowlatency", pkgver:"5.0.0-31.33~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"5.0.0.31.88")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"5.0.0.31.88")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1020.9")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"5.0.0.31.88")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"5.0.0.31.88")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"5.0.0.31.88")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1018-aws", pkgver:"5.0.0-1018.20")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1019-kvm", pkgver:"5.0.0-1019.20")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1019-raspi2", pkgver:"5.0.0-1019.19")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1020-gcp", pkgver:"5.0.0-1020.20")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1022-azure", pkgver:"5.0.0-1022.23")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1023-snapdragon", pkgver:"5.0.0-1023.24")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-31-generic", pkgver:"5.0.0-31.33")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-31-generic-lpae", pkgver:"5.0.0-31.33")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-31-lowlatency", pkgver:"5.0.0-31.33")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-aws", pkgver:"5.0.0.1018.19")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1022.21")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-gcp", pkgver:"5.0.0.1020.46")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-generic", pkgver:"5.0.0.31.32")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-generic-lpae", pkgver:"5.0.0.31.32")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-gke", pkgver:"5.0.0.1020.46")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-kvm", pkgver:"5.0.0.1019.19")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-lowlatency", pkgver:"5.0.0.31.32")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-raspi2", pkgver:"5.0.0.1019.16")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-snapdragon", pkgver:"5.0.0.1023.16")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-virtual", pkgver:"5.0.0.31.32")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.0-aws / linux-image-5.0-azure / linux-image-5.0-gcp / etc");
}
