#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4439-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139027);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-12380", "CVE-2019-16089", "CVE-2019-19036", "CVE-2019-19462", "CVE-2019-20810", "CVE-2019-20908", "CVE-2020-10732", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-11935", "CVE-2020-13974", "CVE-2020-15780");
  script_xref(name:"USN", value:"4439-1");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel vulnerabilities (USN-4439-1)");
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
"It was discovered that the network block device (nbd) implementation
in the Linux kernel did not properly check for error conditions in
some situations. An attacker could possibly use this to cause a denial
of service (system crash). (CVE-2019-16089) It was discovered that the
btrfs file system implementation in the Linux kernel did not properly
validate file system metadata in some situations. An attacker could
use this to construct a malicious btrfs image that, when mounted,
could cause a denial of service (system crash). (CVE-2019-19036) It
was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly check return values in some situations.
A local attacker could possibly use this to cause a denial of service
(system crash). (CVE-2019-19462) Chuhong Yuan discovered that go7007
USB audio device driver in the Linux kernel did not properly
deallocate memory in some failure conditions. A physically proximate
attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-20810) It was discovered that the elf handling
code in the Linux kernel did not initialize memory before using it in
certain situations. A local attacker could use this to possibly expose
sensitive information (kernel memory). (CVE-2020-10732) Fan Yang
discovered that the mremap implementation in the Linux kernel did not
properly handle DAX Huge Pages. A local attacker with access to DAX
storage could use this to gain administrative privileges.
(CVE-2020-10757) It was discovered that the Linux kernel did not
correctly apply Speculative Store Bypass Disable (SSBD) mitigations in
certain situations. A local attacker could possibly use this to expose
sensitive information. (CVE-2020-10766) It was discovered that the
Linux kernel did not correctly apply Indirect Branch Predictor Barrier
(IBPB) mitigations in certain situations. A local attacker could
possibly use this to expose sensitive information. (CVE-2020-10767) It
was discovered that the Linux kernel could incorrectly enable indirect
branch speculation after it has been disabled for a process via a
prctl() call. A local attacker could possibly use this to expose
sensitive information. (CVE-2020-10768) Mauricio Faria de Oliveira
discovered that the aufs implementation in the Linux kernel improperly
managed inode reference counts in the vfsub_dentry_open() method. A
local attacker could use this vulnerability to cause a denial of
service. (CVE-2020-11935) It was discovered that the Virtual Terminal
keyboard driver in the Linux kernel contained an integer overflow. A
local attacker could possibly use this to have an unspecified impact.
(CVE-2020-13974) It was discovered that the efi subsystem in the Linux
kernel did not handle memory allocation failures during early boot in
some situations. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2019-12380) Jason A. Donenfeld
discovered that the ACPI implementation in the Linux kernel did not
properly restrict loading SSDT code from an EFI variable. A privileged
attacker could use this to bypass Secure Boot lockdown restrictions
and execute arbitrary code in the kernel. (CVE-2019-20908) Jason A.
Donenfeld discovered that the ACPI implementation in the Linux kernel
did not properly restrict loading ACPI tables via configfs. A
privileged attacker could use this to bypass Secure Boot lockdown
restrictions and execute arbitrary code in the kernel.
(CVE-2020-15780).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4439-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15780");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.0-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-12380", "CVE-2019-16089", "CVE-2019-19036", "CVE-2019-19462", "CVE-2019-20810", "CVE-2019-20908", "CVE-2020-10732", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-11935", "CVE-2020-13974", "CVE-2020-15780");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4439-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1045-gke", pkgver:"5.0.0-1045.46")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.0.0-1065-oem-osp1", pkgver:"5.0.0-1065.70")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke-5.0", pkgver:"5.0.0.1045.30")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem-osp1", pkgver:"5.0.0.1065.63")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.0-gke / linux-image-5.0-oem-osp1 / etc");
}
