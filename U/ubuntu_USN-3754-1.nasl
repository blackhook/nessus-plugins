#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3754-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112113);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2016-10208", "CVE-2017-11472", "CVE-2017-11473", "CVE-2017-14991", "CVE-2017-15649", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538", "CVE-2017-16643", "CVE-2017-16644", "CVE-2017-16645", "CVE-2017-16650", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-17558", "CVE-2017-18255", "CVE-2017-18270", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2671", "CVE-2017-5549", "CVE-2017-5897", "CVE-2017-6345", "CVE-2017-6348", "CVE-2017-7518", "CVE-2017-7645", "CVE-2017-8831", "CVE-2017-9984", "CVE-2017-9985", "CVE-2018-1000204", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-10323", "CVE-2018-10675", "CVE-2018-10877", "CVE-2018-10881", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-10940", "CVE-2018-12233", "CVE-2018-13094", "CVE-2018-13405", "CVE-2018-13406");
  script_xref(name:"USN", value:"3754-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-3754-1)");
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
"Ralf Spenneberg discovered that the ext4 implementation in the Linux
kernel did not properly validate meta block groups. An attacker with
physical access could use this to specially craft an ext4 image that
causes a denial of service (system crash). (CVE-2016-10208)

It was discovered that an information disclosure vulnerability existed
in the ACPI implementation of the Linux kernel. A local attacker could
use this to expose sensitive information (kernel memory addresses).
(CVE-2017-11472)

It was discovered that a buffer overflow existed in the ACPI table
parsing implementation in the Linux kernel. A local attacker could use
this to construct a malicious ACPI table that, when loaded, caused a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-11473)

It was discovered that the generic SCSI driver in the Linux kernel did
not properly initialize data returned to user space in some
situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2017-14991)

It was discovered that a race condition existed in the packet fanout
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-15649)

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

Andrey Konovalov discovered that the USB subsystem in the Linux kernel
did not properly validate USB interface association descriptors. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2017-16531)

Andrey Konovalov discovered that the usbtest device driver in the
Linux kernel did not properly validate endpoint metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16532)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel
did not properly validate USB HID descriptors. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2017-16533)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel
did not properly validate USB BOS metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2017-16535)

Andrey Konovalov discovered that the Conexant cx231xx USB video
capture driver in the Linux kernel did not properly validate interface
descriptors. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2017-16536)

Andrey Konovalov discovered that the SoundGraph iMON USB driver in the
Linux kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-16537)

It was discovered that the DM04/QQBOX USB driver in the Linux kernel
did not properly handle device attachment and warm-start. A physically
proximate attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2017-16538)

Andrey Konovalov discovered an out-of-bounds read in the GTCO
digitizer USB driver for the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-16643)

Andrey Konovalov discovered that the video4linux driver for Hauppauge
HD PVR USB devices in the Linux kernel did not properly handle some
error conditions. A physically proximate attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-16644)

Andrey Konovalov discovered that the IMS Passenger Control Unit USB
driver in the Linux kernel did not properly validate device
descriptors. A physically proximate attacker could use this to cause a
denial of service (system crash). (CVE-2017-16645)

Andrey Konovalov discovered that the QMI WWAN USB driver did not
properly validate device descriptors. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2017-16650)

It was discovered that the USB Virtual Host Controller Interface
(VHCI) driver in the Linux kernel contained an information disclosure
vulnerability. A physically proximate attacker could use this to
expose sensitive information (kernel memory). (CVE-2017-16911)

It was discovered that the USB over IP implementation in the Linux
kernel did not validate endpoint numbers. A remote attacker could use
this to cause a denial of service (system crash). (CVE-2017-16912)

It was discovered that the USB over IP implementation in the Linux
kernel did not properly validate CMD_SUBMIT packets. A remote attacker
could use this to cause a denial of service (excessive memory
consumption). (CVE-2017-16913)

It was discovered that the USB over IP implementation in the Linux
kernel contained a NULL pointer dereference error. A remote attacker
could use this to cause a denial of service (system crash).
(CVE-2017-16914)

It was discovered that the core USB subsystem in the Linux kernel did
not validate the number of configurations and interfaces in a device.
A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2017-17558)

It was discovered that an integer overflow existed in the perf
subsystem of the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2017-18255)

It was discovered that the keyring subsystem in the Linux kernel did
not properly prevent a user from creating keyrings for other users. A
local attacker could use this cause a denial of service or expose
sensitive information. (CVE-2017-18270)

Andy Lutomirski and Willy Tarreau discovered that the KVM
implementation in the Linux kernel did not properly emulate
instructions on the SS segment register. A local attacker in a guest
virtual machine could use this to cause a denial of service (guest OS
crash) or possibly gain administrative privileges in the guest OS.
(CVE-2017-2583)

Dmitry Vyukov discovered that the KVM implementation in the Linux
kernel improperly emulated certain instructions. A local attacker
could use this to obtain sensitive information (kernel memory).
(CVE-2017-2584)

It was discovered that the KLSI KL5KUSB105 serial-to-USB device driver
in the Linux kernel did not properly initialize memory related to
logging. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2017-5549)

Andrey Konovalov discovered an out-of-bounds access in the IPv6
Generic Routing Encapsulation (GRE) tunneling implementation in the
Linux kernel. An attacker could use this to possibly expose sensitive
information. (CVE-2017-5897)

Andrey Konovalov discovered that the LLC subsytem in the Linux kernel
did not properly set up a destructor in certain situations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-6345)

Dmitry Vyukov discovered race conditions in the Infrared (IrDA)
subsystem in the Linux kernel. A local attacker could use this to
cause a denial of service (deadlock). (CVE-2017-6348)

Andy Lutomirski discovered that the KVM implementation in the Linux
kernel was vulnerable to a debug exception error when single-stepping
through a syscall. A local attacker in a non-Linux guest vm could
possibly use this to gain administrative privileges in the guest vm.
(CVE-2017-7518)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3
server implementations in the Linux kernel did not properly handle
certain long RPC replies. A remote attacker could use this to cause a
denial of service (system crash). (CVE-2017-7645)

Pengfei Wang discovered that a race condition existed in the NXP
SAA7164 TV Decoder driver for the Linux kernel. A local attacker could
use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-8831)

Pengfei Wang discovered that the Turtle Beach MultiSound audio device
driver in the Linux kernel contained race conditions when fetching
from the ring-buffer. A local attacker could use this to cause a
denial of service (infinite loop). (CVE-2017-9984, CVE-2017-9985)

It was discovered that the wait4() system call in the Linux kernel did
not properly validate its arguments in some situations. A local
attacker could possibly use this to cause a denial of service.
(CVE-2018-10087)

It was discovered that the kill() system call implementation in the
Linux kernel did not properly validate its arguments in some
situations. A local attacker could possibly use this to cause a denial
of service. (CVE-2018-10124)

Wen Xu discovered that the XFS filesystem implementation in the Linux
kernel did not properly validate meta-data information. An attacker
could use this to construct a malicious xfs image that, when mounted,
could cause a denial of service (system crash). (CVE-2018-10323)

Zhong Jiang discovered that a use-after-free vulnerability existed in
the NUMA memory policy implementation in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-10675)

Wen Xu discovered that a buffer overflow existed in the ext4
filesystem implementation in the Linux kernel. An attacker could use
this to construct a malicious ext4 image that, when mounted, could
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-10877)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly keep meta-data information consistent in some
situations. An attacker could use this to construct a malicious ext4
image that, when mounted, could cause a denial of service (system
crash). (CVE-2018-10881)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly handle corrupted meta data in some situations.
An attacker could use this to specially craft an ext4 filesystem that
caused a denial of service (system crash) when mounted.
(CVE-2018-1092)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly handle corrupted meta data in some situations.
An attacker could use this to specially craft an ext4 filesystem that
caused a denial of service (system crash) when mounted.
(CVE-2018-1093)

It was discovered that the cdrom driver in the Linux kernel contained
an incorrect bounds check. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-10940)

Shankara Pailoor discovered that the JFS filesystem implementation in
the Linux kernel contained a buffer overflow when handling extended
attributes. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2018-12233)

Wen Xu discovered that the XFS filesystem implementation in the Linux
kernel did not properly handle an error condition with a corrupted xfs
image. An attacker could use this to construct a malicious xfs image
that, when mounted, could cause a denial of service (system crash).
(CVE-2018-13094)

It was discovered that the Linux kernel did not properly handle setgid
file creation when performed by a non-member of the group. A local
attacker could use this to gain elevated privileges. (CVE-2018-13405)

Silvio Cesare discovered that the generic VESA frame buffer driver in
the Linux kernel contained an integer overflow. A local attacker could
use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2018-13406)

Daniel Jiang discovered that a race condition existed in the ipv4 ping
socket implementation in the Linux kernel. A local privileged attacker
could use this to cause a denial of service (system crash).
(CVE-2017-2671)

It was discovered that an information leak existed in the generic SCSI
driver in the Linux kernel. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-1000204)

It was discovered that a memory leak existed in the Serial Attached
SCSI (SAS) implementation in the Linux kernel. A physically proximate
attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2018-10021).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3754-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2016-10208", "CVE-2017-11472", "CVE-2017-11473", "CVE-2017-14991", "CVE-2017-15649", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538", "CVE-2017-16643", "CVE-2017-16644", "CVE-2017-16645", "CVE-2017-16650", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-17558", "CVE-2017-18255", "CVE-2017-18270", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2671", "CVE-2017-5549", "CVE-2017-5897", "CVE-2017-6345", "CVE-2017-6348", "CVE-2017-7518", "CVE-2017-7645", "CVE-2017-8831", "CVE-2017-9984", "CVE-2017-9985", "CVE-2018-1000204", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-10323", "CVE-2018-10675", "CVE-2018-10877", "CVE-2018-10881", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-10940", "CVE-2018-12233", "CVE-2018-13094", "CVE-2018-13405", "CVE-2018-13406");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3754-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-157-generic", pkgver:"3.13.0-157.207")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-157-generic-lpae", pkgver:"3.13.0-157.207")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-157-lowlatency", pkgver:"3.13.0-157.207")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic", pkgver:"3.13.0.157.167")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae", pkgver:"3.13.0.157.167")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency", pkgver:"3.13.0.157.167")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae / etc");
}
