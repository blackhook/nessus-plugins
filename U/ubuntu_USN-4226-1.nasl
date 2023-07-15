#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4226-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132690);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-10220", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-16231", "CVE-2019-16233", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-18660", "CVE-2019-18813", "CVE-2019-19045", "CVE-2019-19048", "CVE-2019-19052", "CVE-2019-19055", "CVE-2019-19060", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19072", "CVE-2019-19075", "CVE-2019-19083", "CVE-2019-19524", "CVE-2019-19526", "CVE-2019-19529", "CVE-2019-19532", "CVE-2019-19534", "CVE-2019-19922", "CVE-2019-2214");
  script_xref(name:"USN", value:"4226-1");

  script_name(english:"Ubuntu 18.04 LTS / 19.04 : linux, linux-aws, linux-aws-5.0, linux-azure, linux-gcp, linux-gke-5.0, (USN-4226-1)");
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
"Michael Hanselmann discovered that the CIFS implementation in the
Linux kernel did not sanitize paths returned by an SMB server. An
attacker controlling an SMB server could use this to overwrite
arbitrary files. (CVE-2019-10220)

It was discovered that a heap-based buffer overflow existed in the
Marvell WiFi-Ex Driver for the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2019-14895, CVE-2019-14901)

It was discovered that a heap-based buffer overflow existed in the
Marvell Libertas WLAN Driver for the Linux kernel. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2019-14896,
CVE-2019-14897)

It was discovered that the Fujitsu ES network device driver for the
Linux kernel did not properly check for errors in some situations,
leading to a NULL pointer dereference. A local attacker could use this
to cause a denial of service. (CVE-2019-16231)

It was discovered that the QLogic Fibre Channel driver in the Linux
kernel did not properly check for error, leading to a NULL pointer
dereference. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2019-16233)

Nicolas Waisman discovered that the WiFi driver stack in the Linux
kernel did not properly validate SSID lengths. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2019-17133)

Anthony Steinhauser discovered that the Linux kernel did not properly
perform Spectre_RSB mitigations to all processors for PowerPC
architecture systems in some situations. A local attacker could use
this to expose sensitive information. (CVE-2019-18660)

It was discovered that the Mellanox Technologies Innova driver in the
Linux kernel did not properly deallocate memory in certain failure
conditions. A local attacker could use this to cause a denial of
service (kernel memory exhaustion). (CVE-2019-19045)

It was discovered that the VirtualBox guest driver implementation in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2019-19048)

It was discovered that Geschwister Schneider USB CAN interface driver
in the Linux kernel did not properly deallocate memory in certain
failure conditions. A physically proximate attacker could use this to
cause a denial of service (kernel memory exhaustion). (CVE-2019-19052)

It was discovered that the netlink-based 802.11 configuration
interface in the Linux kernel did not deallocate memory in certain
error conditions. A local attacker could possibly use this to cause a
denial of service (kernel memory exhaustion). (CVE-2019-19055)

It was discovered that the ADIS16400 IIO IMU Driver for the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19060)

It was discovered that the Intel OPA Gen1 Infiniband Driver for the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2019-19065)

It was discovered that the AMD Audio CoProcessor Driver for the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker with the ability to load modules could use this to
cause a denial of service (memory exhaustion). (CVE-2019-19067)

It was discovered that the event tracing subsystem of the Linux kernel
did not properly deallocate memory in certain error conditions. A
local attacker could use this to cause a denial of service (kernel
memory exhaustion). (CVE-2019-19072)

It was discovered that the Cascoda CA8210 SPI 802.15.4 wireless
controller driver for the Linux kernel did not properly deallocate
memory in certain error conditions. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2019-19075)

It was discovered that the AMD Display Engine Driver in the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attack could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19083)

It was discovered that the driver for memoryless force-feedback input
devices in the Linux kernel contained a use-after-free vulnerability.
A physically proximate attacker could possibly use this to cause a
denial of service (system crash) or execute arbitrary code.
(CVE-2019-19524)

It was discovered that the NXP PN533 NFC USB driver in the Linux
kernel did not properly free resources after a late probe error,
leading to a use- after-free vulnerability. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2019-19526)

It was discovered that the Microchip CAN BUS Analyzer driver in the
Linux kernel contained a use-after-free vulnerability on device
disconnect. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2019-19529)

It was discovered that multiple USB HID device drivers in the Linux
kernel did not properly validate device metadata on attachment,
leading to out-of- bounds writes. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2019-19532)

It was discovered that the PEAK-System Technik USB driver in the Linux
kernel did not properly sanitize memory before sending it to the
device. A physically proximate attacker could use this to expose
sensitive information (kernel memory). (CVE-2019-19534)

It was discovered that in some situations the fair scheduler in the
Linux kernel did not permit a process to use its full quota time
slice. A local attacker could use this to cause a denial of service.
(CVE-2019-19922)

It was discovered that the binder IPC implementation in the Linux
kernel did not properly perform bounds checking in some situations,
leading to an out-of-bounds write. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-2214)

Nicolas Waisman discovered that the Chelsio T4/T5 RDMA Driver for the
Linux kernel performed DMA from a kernel stack. A local attacker could
use this to cause a denial of service (system crash). (CVE-2019-17075)

It was discovered that the DesignWare USB3 controller driver in the
Linux kernel did not properly deallocate memory in some error
conditions. A local attacker could possibly use this to cause a denial
of service (memory exhaustion). (CVE-2019-18813).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4226-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/07");
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
if (! preg(pattern:"^(18\.04|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-10220", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-16231", "CVE-2019-16233", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-18660", "CVE-2019-18813", "CVE-2019-19045", "CVE-2019-19048", "CVE-2019-19052", "CVE-2019-19055", "CVE-2019-19060", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19072", "CVE-2019-19075", "CVE-2019-19083", "CVE-2019-19524", "CVE-2019-19526", "CVE-2019-19529", "CVE-2019-19532", "CVE-2019-19534", "CVE-2019-19922", "CVE-2019-2214");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4226-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1009-oracle", pkgver:"5.0.0-1009.14~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1023-aws", pkgver:"5.0.0-1023.26~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1027-gke", pkgver:"5.0.0-1027.28~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1028-azure", pkgver:"5.0.0-1028.30~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1033-oem-osp1", pkgver:"5.0.0-1033.38")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws-edge", pkgver:"5.0.0.1023.37")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1028.39")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1027.16")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem-osp1", pkgver:"5.0.0.1033.37")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oracle-edge", pkgver:"5.0.0.1009.8")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1009-oracle", pkgver:"5.0.0-1009.14")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1023-aws", pkgver:"5.0.0-1023.26")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1024-kvm", pkgver:"5.0.0-1024.26")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1024-raspi2", pkgver:"5.0.0-1024.25")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1028-azure", pkgver:"5.0.0-1028.30")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-1028-gcp", pkgver:"5.0.0-1028.29")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-38-generic", pkgver:"5.0.0-38.41")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-38-generic-lpae", pkgver:"5.0.0-38.41")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-5.0.0-38-lowlatency", pkgver:"5.0.0-38.41")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-aws", pkgver:"5.0.0.1023.25")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1028.28")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-gcp", pkgver:"5.0.0.1028.53")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-generic", pkgver:"5.0.0.38.40")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-generic-lpae", pkgver:"5.0.0.38.40")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-gke", pkgver:"5.0.0.1028.53")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-kvm", pkgver:"5.0.0.1024.25")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-lowlatency", pkgver:"5.0.0.38.40")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-oracle", pkgver:"5.0.0.1009.35")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-raspi2", pkgver:"5.0.0.1024.22")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"linux-image-virtual", pkgver:"5.0.0.38.40")) flag++;

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
