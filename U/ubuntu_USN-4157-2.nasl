#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4157-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130147);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-15504", "CVE-2019-15505", "CVE-2019-15902", "CVE-2019-16714", "CVE-2019-2181");
  script_xref(name:"USN", value:"4157-2");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel (HWE) vulnerabilities (USN-4157-2)");
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
"USN-4157-1 fixed vulnerabilities in the Linux kernel for Ubuntu 19.04.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 19.04 for Ubuntu 18.04 LTS.

Wen Huang discovered that the Marvell Wi-Fi device driver in the Linux
kernel did not properly perform bounds checking, leading to a heap
overflow. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-14814,
CVE-2019-14815, CVE-2019-14816)

Matt Delco discovered that the KVM hypervisor implementation in the
Linux kernel did not properly perform bounds checking when handling
coalesced MMIO write operations. A local attacker with write access to
/dev/kvm could use this to cause a denial of service (system crash).
(CVE-2019-14821)

Hui Peng and Mathias Payer discovered that the 91x Wi-Fi driver in the
Linux kernel did not properly handle error conditions on
initialization, leading to a double-free vulnerability. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2019-15504)

It was discovered that the Technisat DVB-S/S2 USB device driver in the
Linux kernel contained a buffer overread. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly expose sensitive information. (CVE-2019-15505)

Brad Spengler discovered that a Spectre mitigation was improperly
implemented in the ptrace susbsystem of the Linux kernel. A local
attacker could possibly use this to expose sensitive information.
(CVE-2019-15902)

It was discovered that the IPv6 RDS implementation in the Linux kernel
did not properly initialize fields in a data structure returned to
user space. A local attacker could use this to expose sensitive
information (kernel memory). Please note that the RDS protocol is
blacklisted in Ubuntu by default. (CVE-2019-16714)

It was discovered that an integer overflow existed in the Binder
implementation of the Linux kernel, leading to a buffer overflow. A
local attacker could use this to escalate privileges. (CVE-2019-2181).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4157-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/22");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-15504", "CVE-2019-15505", "CVE-2019-15902", "CVE-2019-16714", "CVE-2019-2181");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4157-2");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1021-gcp", pkgver:"5.0.0-1021.21~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1023-azure", pkgver:"5.0.0-1023.24~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1023-gke", pkgver:"5.0.0-1023.23~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-32-generic", pkgver:"5.0.0-32.34~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-32-generic-lpae", pkgver:"5.0.0-32.34~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-32-lowlatency", pkgver:"5.0.0-32.34~18.04.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-azure", pkgver:"5.0.0.1023.33")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"5.0.0.1021.26")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-hwe-18.04", pkgver:"5.0.0.32.89")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-generic-lpae-hwe-18.04", pkgver:"5.0.0.32.89")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1023.12")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-lowlatency-hwe-18.04", pkgver:"5.0.0.32.89")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-snapdragon-hwe-18.04", pkgver:"5.0.0.32.89")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-virtual-hwe-18.04", pkgver:"5.0.0.32.89")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.0-azure / linux-image-5.0-gcp / etc");
}
