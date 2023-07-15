#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3469-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104321);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-10911", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12192", "CVE-2017-14051", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-14991", "CVE-2017-15537", "CVE-2017-9984", "CVE-2017-9985");
  script_xref(name:"USN", value:"3469-2");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-xenial vulnerabilities (USN-3469-2)");
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
"USN-3469-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

Anthony Perard discovered that the Xen virtual block driver did not
properly initialize some data structures before passing them to user
space. A local attacker in a guest VM could use this to expose
sensitive information from the host OS or other guest VMs.
(CVE-2017-10911)

Bo Zhang discovered that the netlink wireless configuration interface
in the Linux kernel did not properly validate attributes when handling
certain requests. A local attacker with the CAP_NET_ADMIN could use
this to cause a denial of service (system crash). (CVE-2017-12153)

It was discovered that the nested KVM implementation in the Linux
kernel in some situations did not properly prevent second level guests
from reading and writing the hardware CR8 register. A local attacker
in a guest could use this to cause a denial of service (system crash).

It was discovered that the key management subsystem in the Linux
kernel did not properly restrict key reads on negatively instantiated
keys. A local attacker could use this to cause a denial of service
(system crash). (CVE-2017-12192)

It was discovered that an integer overflow existed in the sysfs
interface for the QLogic 24xx+ series SCSI driver in the Linux kernel.
A local privileged attacker could use this to cause a denial of
service (system crash). (CVE-2017-14051)

It was discovered that the ATI Radeon framebuffer driver in the Linux
kernel did not properly initialize a data structure returned to user
space. A local attacker could use this to expose sensitive information
(kernel memory). (CVE-2017-14156)

Dave Chinner discovered that the XFS filesystem did not enforce that
the realtime inode flag was settable only on filesystems on a realtime
device. A local attacker could use this to cause a denial of service
(system crash). (CVE-2017-14340)

ChunYu Wang discovered that the iSCSI transport implementation in the
Linux kernel did not properly validate data structures. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-14489)

It was discovered that the generic SCSI driver in the Linux kernel did
not properly initialize data returned to user space in some
situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2017-14991)

Dmitry Vyukov discovered that the Floating Point Unit (fpu) subsystem
in the Linux kernel did not properly handle attempts to set reserved
bits in a task's extended state (xstate) area. A local attacker could
use this to cause a denial of service (system crash). (CVE-2017-15537)

Pengfei Wang discovered that the Turtle Beach MultiSound audio device
driver in the Linux kernel contained race conditions when fetching
from the ring-buffer. A local attacker could use this to cause a
denial of service (infinite loop). (CVE-2017-9984, CVE-2017-9985).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3469-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-10911", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12192", "CVE-2017-14051", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-14991", "CVE-2017-15537", "CVE-2017-9984", "CVE-2017-9985");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3469-2");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-98-generic", pkgver:"4.4.0-98.121~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-98-generic-lpae", pkgver:"4.4.0-98.121~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-98-lowlatency", pkgver:"4.4.0-98.121~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae-lts-xenial", pkgver:"4.4.0.98.82")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lts-xenial", pkgver:"4.4.0.98.82")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency-lts-xenial", pkgver:"4.4.0.98.82")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-generic / linux-image-4.4-generic-lpae / etc");
}
