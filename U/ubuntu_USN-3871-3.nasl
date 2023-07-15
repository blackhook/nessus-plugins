#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3871-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121593);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-14625", "CVE-2018-16882", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-19407", "CVE-2018-9516");
  script_xref(name:"USN", value:"3871-3");

  script_name(english:"Ubuntu 18.04 LTS : linux-aws, linux-gcp, linux-kvm, linux-oem, linux-raspi2 vulnerabilities (USN-3871-3)");
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
"Wen Xu discovered that a use-after-free vulnerability existed in the
ext4 filesystem implementation in the Linux kernel. An attacker could
use this to construct a malicious ext4 image that, when mounted, could
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-10876, CVE-2018-10879)

Wen Xu discovered that a buffer overflow existed in the ext4
filesystem implementation in the Linux kernel. An attacker could use
this to construct a malicious ext4 image that, when mounted, could
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-10877)

Wen Xu discovered that an out-of-bounds write vulnerability existed in
the ext4 filesystem implementation in the Linux kernel. An attacker
could use this to construct a malicious ext4 image that, when mounted,
could cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-10878, CVE-2018-10882)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly ensure that xattr information remained in
inode bodies. An attacker could use this to construct a malicious ext4
image that, when mounted, could cause a denial of service (system
crash). (CVE-2018-10880)

Wen Xu discovered that the ext4 file system implementation in the
Linux kernel could possibly perform an out of bounds write when
updating the journal for an inline file. An attacker could use this to
construct a malicious ext4 image that, when mounted, could cause a
denial of service (system crash). (CVE-2018-10883)

It was discovered that a race condition existed in the vsock address
family implementation of the Linux kernel that could lead to a
use-after-free condition. A local attacker in a guest virtual machine
could use this to expose sensitive information (host machine kernel
memory). (CVE-2018-14625)

Cfir Cohen discovered that a use-after-free vulnerability existed in
the KVM implementation of the Linux kernel, when handling interrupts
in environments where nested virtualization is in use (nested KVM
virtualization is not enabled by default in Ubuntu kernels). A local
attacker in a guest VM could possibly use this to gain administrative
privileges in a host machine. (CVE-2018-16882)

Jann Horn discovered that the procfs file system implementation in the
Linux kernel did not properly restrict the ability to inspect the
kernel stack of an arbitrary task. A local attacker could use this to
expose sensitive information. (CVE-2018-17972)

Jann Horn discovered that the mremap() system call in the Linux kernel
did not properly flush the TLB when completing, potentially leaving
access to a physical page after it has been released to the page
allocator. A local attacker could use this to cause a denial of
service (system crash), expose sensitive information, or possibly
execute arbitrary code. (CVE-2018-18281)

Wei Wu discovered that the KVM implementation in the Linux kernel did
not properly ensure that ioapics were initialized. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2018-19407)

It was discovered that the debug interface for the Linux kernel's HID
subsystem did not properly perform bounds checking in some situations.
An attacker with access to debugfs could use this to cause a denial of
service or possibly gain additional privileges. (CVE-2018-9516).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3871-3/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9516");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/05");
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
  cve_list = make_list("CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-14625", "CVE-2018-16882", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-19407", "CVE-2018-9516");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3871-3");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1027-gcp", pkgver:"4.15.0-1027.28")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1029-kvm", pkgver:"4.15.0-1029.29")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1031-raspi2", pkgver:"4.15.0-1031.33")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1032-aws", pkgver:"4.15.0-1032.34")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-4.15.0-1033-oem", pkgver:"4.15.0-1033.38")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-aws", pkgver:"4.15.0.1032.31")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gcp", pkgver:"4.15.0.1027.29")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-gke", pkgver:"4.15.0.1027.29")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-kvm", pkgver:"4.15.0.1029.29")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-oem", pkgver:"4.15.0.1033.38")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2", pkgver:"4.15.0.1031.29")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.15-aws / linux-image-4.15-gcp / linux-image-4.15-kvm / etc");
}
