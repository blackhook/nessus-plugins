#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4208-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131562);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-15794", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-18810", "CVE-2019-19048", "CVE-2019-19060", "CVE-2019-19061", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19069", "CVE-2019-19075", "CVE-2019-19083");
  script_xref(name:"USN", value:"4208-1");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 : linux, linux-aws, linux-gcp, linux-gcp-5.3, linux-kvm, linux-oracle (USN-4208-1)");
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
"Jann Horn discovered that the OverlayFS and ShiftFS Drivers in the
Linux kernel did not properly handle reference counting during memory
mapping operations when used in conjunction with AUFS. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2019-15794)

Nicolas Waisman discovered that the WiFi driver stack in the Linux
kernel did not properly validate SSID lengths. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2019-17133)

It was discovered that the ARM Komeda display driver for the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-18810)

It was discovered that the VirtualBox guest driver implementation in
the Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2019-19048)

It was discovered that the ADIS16400 IIO IMU Driver for the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19060, CVE-2019-19061)

It was discovered that the Intel OPA Gen1 Infiniband Driver for the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2019-19065)

It was discovered that the AMD Audio CoProcessor Driver for the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attacker with the ability to load modules could use this to
cause a denial of service (memory exhaustion). (CVE-2019-19067)

It was discovered in the Qualcomm FastRPC Driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19069)

It was discovered that the Cascoda CA8210 SPI 802.15.4 wireless
controller driver for the Linux kernel did not properly deallocate
memory in certain error conditions. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2019-19075)

It was discovered that the AMD Display Engine Driver in the Linux
kernel did not properly deallocate memory in certain error conditions.
A local attack could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19083)

Nicolas Waisman discovered that the Chelsio T4/T5 RDMA Driver for the
Linux kernel performed DMA from a kernel stack. A local attacker could
use this to cause a denial of service (system crash). (CVE-2019-17075).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4208-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17133");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
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
if (! preg(pattern:"^(18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-15794", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-18810", "CVE-2019-19048", "CVE-2019-19060", "CVE-2019-19061", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19069", "CVE-2019-19075", "CVE-2019-19083");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4208-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1009-gcp", pkgver:"5.3.0-1009.10~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp-edge", pkgver:"5.3.0.1009.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1007-oracle", pkgver:"5.3.0-1007.8")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1008-aws", pkgver:"5.3.0-1008.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1008-kvm", pkgver:"5.3.0-1008.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1009-gcp", pkgver:"5.3.0-1009.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-24-generic", pkgver:"5.3.0-24.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-24-generic-lpae", pkgver:"5.3.0-24.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-24-lowlatency", pkgver:"5.3.0-24.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-24-snapdragon", pkgver:"5.3.0-24.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-aws", pkgver:"5.3.0.1008.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gcp", pkgver:"5.3.0.1009.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic", pkgver:"5.3.0.24.28")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic-lpae", pkgver:"5.3.0.24.28")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gke", pkgver:"5.3.0.1009.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-kvm", pkgver:"5.3.0.1008.10")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-lowlatency", pkgver:"5.3.0.24.28")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-oracle", pkgver:"5.3.0.1007.8")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-snapdragon", pkgver:"5.3.0.24.28")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-virtual", pkgver:"5.3.0.24.28")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.3-aws / linux-image-5.3-gcp / linux-image-5.3-generic / etc");
}
