#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4183-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130963);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11135", "CVE-2019-15791", "CVE-2019-15792", "CVE-2019-15793", "CVE-2019-16746", "CVE-2019-17666");
  script_xref(name:"USN", value:"4183-1");

  script_name(english:"Ubuntu 19.10 : Linux kernel vulnerabilities (USN-4183-1)");
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
"Stephan van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro
Frigo, Kaveh Razavi, Herbert Bos, Cristiano Giuffrida, Giorgi
Maisuradze, Moritz Lipp, Michael Schwarz, Daniel Gruss, and Jo Van
Bulck discovered that Intel processors using Transactional
Synchronization Extensions (TSX) could expose memory contents
previously stored in microarchitectural buffers to a malicious process
that is executing on the same CPU core. A local attacker could use
this to expose sensitive information. (CVE-2019-11135)

It was discovered that the Intel i915 graphics chipsets allowed
userspace to modify page table entries via writes to MMIO from the
Blitter Command Streamer and expose kernel memory information. A local
attacker could use this to expose sensitive information or possibly
elevate privileges. (CVE-2019-0155)

Deepak Gupta discovered that on certain Intel processors, the Linux
kernel did not properly perform invalidation on page table updates by
virtual guest operating systems. A local attacker in a guest VM could
use this to cause a denial of service (host system crash).
(CVE-2018-12207)

It was discovered that the Intel i915 graphics chipsets could cause a
system hang when userspace performed a read from GT memory mapped
input output (MMIO) when the product is in certain low power states. A
local attacker could use this to cause a denial of service.
(CVE-2019-0154)

Jann Horn discovered a reference count underflow in the shiftfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15791)

Jann Horn discovered a type confusion vulnerability in the shiftfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15792)

Jann Horn discovered that the shiftfs implementation in the Linux
kernel did not use the correct file system uid/gid when the user
namespace of a lower file system is not in the init user namespace. A
local attacker could use this to possibly bypass DAC permissions or
have some other unspecified impact. (CVE-2019-15793)

It was discovered that a buffer overflow existed in the 802.11 Wi-Fi
configuration interface for the Linux kernel when handling beacon
settings. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-16746)

Nico Waisman discovered that a buffer overflow existed in the Realtek
Wi-Fi driver for the Linux kernel when handling Notice of Absence
frames. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2019-17666).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4183-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");
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
if (! preg(pattern:"^(19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11135", "CVE-2019-15791", "CVE-2019-15792", "CVE-2019-15793", "CVE-2019-16746", "CVE-2019-17666");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4183-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1006-oracle", pkgver:"5.3.0-1006.7")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1007-aws", pkgver:"5.3.0-1007.8")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1007-azure", pkgver:"5.3.0-1007.8")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1007-kvm", pkgver:"5.3.0-1007.8")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1008-gcp", pkgver:"5.3.0-1008.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1012-raspi2", pkgver:"5.3.0-1012.14")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-22-generic", pkgver:"5.3.0-22.24")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-22-generic-lpae", pkgver:"5.3.0-22.24")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-22-lowlatency", pkgver:"5.3.0-22.24")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-22-snapdragon", pkgver:"5.3.0-22.24")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-aws", pkgver:"5.3.0.1007.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-azure", pkgver:"5.3.0.1007.25")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gcp", pkgver:"5.3.0.1008.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic", pkgver:"5.3.0.22.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic-lpae", pkgver:"5.3.0.22.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-gke", pkgver:"5.3.0.1008.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-kvm", pkgver:"5.3.0.1007.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-lowlatency", pkgver:"5.3.0.22.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-oracle", pkgver:"5.3.0.1006.7")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-raspi2", pkgver:"5.3.0.1012.9")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-snapdragon", pkgver:"5.3.0.22.26")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-virtual", pkgver:"5.3.0.22.26")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.3-aws / linux-image-5.3-azure / linux-image-5.3-gcp / etc");
}
