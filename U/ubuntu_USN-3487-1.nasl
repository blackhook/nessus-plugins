#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3487-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104737);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-1000255", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12188", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-14954", "CVE-2017-15265", "CVE-2017-15537", "CVE-2017-15649", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16533", "CVE-2017-16534");
  script_xref(name:"USN", value:"3487-1");

  script_name(english:"Ubuntu 17.10 : linux, linux-raspi2 vulnerabilities (USN-3487-1)");
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
"It was discovered that the KVM subsystem in the Linux kernel did not
properly keep track of nested levels in guest page tables. A local
attacker in a guest VM could use this to cause a denial of service
(host OS crash) or possibly execute arbitrary code in the host OS.
(CVE-2017-12188)

It was discovered that on the PowerPC architecture, the kernel did not
properly sanitize the signal stack when handling sigreturn(). A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-1000255)

Bo Zhang discovered that the netlink wireless configuration interface
in the Linux kernel did not properly validate attributes when handling
certain requests. A local attacker with the CAP_NET_ADMIN could use
this to cause a denial of service (system crash). (CVE-2017-12153)

It was discovered that the nested KVM implementation in the Linux
kernel in some situations did not properly prevent second level guests
from reading and writing the hardware CR8 register. A local attacker
in a guest could use this to cause a denial of service (system crash).
(CVE-2017-12154)

Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux
kernel did not properly track reference counts when merging buffers. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2017-12190)

It was discovered that the key management subsystem in the Linux
kernel did not properly restrict key reads on negatively instantiated
keys. A local attacker could use this to cause a denial of service
(system crash). (CVE-2017-12192)

It was discovered that the ATI Radeon framebuffer driver in the Linux
kernel did not properly initialize a data structure returned to user
space. A local attacker could use this to expose sensitive information
(kernel memory). (CVE-2017-14156)

ChunYu Wang discovered that the iSCSI transport implementation in the
Linux kernel did not properly validate data structures. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-14489)

Alexander Potapenko discovered an information leak in the waitid
implementation of the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2017-14954)

It was discovered that a race condition existed in the ALSA subsystem
of the Linux kernel when creating and deleting a port via ioctl(). A
local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-15265)

Dmitry Vyukov discovered that the Floating Point Unit (fpu) subsystem
in the Linux kernel did not properly handle attempts to set reserved
bits in a task's extended state (xstate) area. A local attacker could
use this to cause a denial of service (system crash). (CVE-2017-15537)

It was discovered that a race condition existed in the packet fanout
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-15649)

Andrey Konovalov discovered a use-after-free vulnerability in the USB
serial console driver in the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-16525)

Andrey Konovalov discovered that the Ultra Wide Band driver in the
Linux kernel did not properly check for an error condition. A
physically proximate attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-16526)

Andrey Konovalov discovered that the ALSA subsystem in the Linux
kernel contained a use-after-free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-16527)

Andrey Konovalov discovered that the ALSA subsystem in the Linux
kernel did not properly validate USB audio buffer descriptors. A
physically proximate attacker could use this cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-16529)

Andrey Konovalov discovered that the USB unattached storage driver in
the Linux kernel contained out-of-bounds error when handling
alternative settings. A physically proximate attacker could use to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-16530)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel
did not properly validate USB interface association descriptors. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2017-16531)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel
did not properly validate USB HID descriptors. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2017-16533)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel
did not properly validate CDC metadata. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-16534).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3487-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.13-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/22");
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
if (! preg(pattern:"^(17\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 17.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-1000255", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12188", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-14954", "CVE-2017-15265", "CVE-2017-15537", "CVE-2017-15649", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16533", "CVE-2017-16534");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3487-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-1006-raspi2", pkgver:"4.13.0-1006.6")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-17-generic", pkgver:"4.13.0-17.20")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-17-generic-lpae", pkgver:"4.13.0-17.20")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-4.13.0-17-lowlatency", pkgver:"4.13.0-17.20")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-generic", pkgver:"4.13.0.17.18")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-generic-lpae", pkgver:"4.13.0.17.18")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-lowlatency", pkgver:"4.13.0.17.18")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"linux-image-raspi2", pkgver:"4.13.0.1006.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.13-generic / linux-image-4.13-generic-lpae / etc");
}
