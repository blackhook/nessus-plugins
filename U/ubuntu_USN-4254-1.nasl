#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4254-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133293);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-14615", "CVE-2019-15291", "CVE-2019-18683", "CVE-2019-18885", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19227", "CVE-2019-19332");
  script_xref(name:"USN", value:"4254-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-4254-1)");
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

It was discovered that a race condition existed in the Virtual Video
Test Driver in the Linux kernel. An attacker with write access to
/dev/video0 on a system with the vivid module loaded could possibly
use this to gain administrative privileges. (CVE-2019-18683)

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

Dan Carpenter discovered that the AppleTalk networking subsystem of
the Linux kernel did not properly handle certain error conditions,
leading to a NULL pointer dereference. A local attacker could use this
to cause a denial of service (system crash). (CVE-2019-19227)

It was discovered that the KVM hypervisor implementation in the Linux
kernel did not properly handle ioctl requests to get emulated CPUID
features. An attacker with access to /dev/kvm could use this to cause
a denial of service (system crash). (CVE-2019-19332)

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
    value:"https://usn.ubuntu.com/4254-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18683");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/28");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-14615", "CVE-2019-15291", "CVE-2019-18683", "CVE-2019-18885", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19227", "CVE-2019-19332");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4254-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1065-kvm", pkgver:"4.4.0-1065.72")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1101-aws", pkgver:"4.4.0-1101.112")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1128-raspi2", pkgver:"4.4.0-1128.137")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1132-snapdragon", pkgver:"4.4.0-1132.140")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-173-generic", pkgver:"4.4.0-173.203")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-173-generic-lpae", pkgver:"4.4.0-173.203")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-173-lowlatency", pkgver:"4.4.0-173.203")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1101.105")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.173.181")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.173.181")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-kvm", pkgver:"4.4.0.1065.65")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.173.181")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-raspi2", pkgver:"4.4.0.1128.128")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1132.124")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-virtual", pkgver:"4.4.0.173.181")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-aws / linux-image-4.4-generic / etc");
}
