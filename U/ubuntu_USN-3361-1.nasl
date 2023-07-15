#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3361-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101929);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2015-1350", "CVE-2016-10208", "CVE-2016-8405", "CVE-2016-8636", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9191", "CVE-2016-9604", "CVE-2016-9755", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2618", "CVE-2017-2671", "CVE-2017-5546", "CVE-2017-5549", "CVE-2017-5550", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6348", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7472", "CVE-2017-7616", "CVE-2017-7618", "CVE-2017-7645", "CVE-2017-7889", "CVE-2017-7895", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9150");
  script_xref(name:"USN", value:"3361-1");

  script_name(english:"Ubuntu 16.04 LTS : linux-hwe vulnerabilities (USN-3361-1)");
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
"USN-3358-1 fixed vulnerabilities in the Linux kernel for Ubuntu 17.04.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 17.04 for Ubuntu 16.04 LTS. Please
note that this update changes the Linux HWE kernel to the 4.10 based
kernel from Ubuntu 17.04, superseding the 4.8 based HWE kernel from
Ubuntu 16.10.

Ben Harris discovered that the Linux kernel would strip extended
privilege attributes of files when performing a failed unprivileged
system call. A local attacker could use this to cause a denial of
service. (CVE-2015-1350)

Ralf Spenneberg discovered that the ext4 implementation in the Linux
kernel did not properly validate meta block groups. An attacker with
physical access could use this to specially craft an ext4 image that
causes a denial of service (system crash). (CVE-2016-10208)

Peter Pi discovered that the colormap handling for frame buffer
devices in the Linux kernel contained an integer overflow. A local
attacker could use this to disclose sensitive information (kernel
memory). (CVE-2016-8405)

It was discovered that an integer overflow existed in the InfiniBand
RDMA over ethernet (RXE) transport implementation in the Linux kernel.
A local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2016-8636)

Vlad Tsyrklevich discovered an integer overflow vulnerability in the
VFIO PCI driver for the Linux kernel. A local attacker with access to
a vfio PCI device file could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2016-9083,
CVE-2016-9084)

CAI Qian discovered that the sysctl implementation in the Linux kernel
did not properly perform reference counting in some situations. An
unprivileged attacker could use this to cause a denial of service
(system hang). (CVE-2016-9191)

It was discovered that the keyring implementation in the Linux kernel
in some situations did not prevent special internal keyrings from
being joined by userspace keyrings. A privileged local attacker could
use this to bypass module verification. (CVE-2016-9604)

Dmitry Vyukov, Andrey Konovalov, Florian Westphal, and Eric Dumazet
discovered that the netfiler subsystem in the Linux kernel mishandled
IPv6 packet reassembly. A local user could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2016-9755)

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

Dmitry Vyukov discovered that KVM implementation in the Linux kernel
improperly emulated the VMXON instruction. A local attacker in a guest
OS could use this to cause a denial of service (memory consumption) in
the host OS. (CVE-2017-2596)

It was discovered that SELinux in the Linux kernel did not properly
handle empty writes to /proc/pid/attr. A local attacker could use this
to cause a denial of service (system crash). (CVE-2017-2618)

Daniel Jiang discovered that a race condition existed in the ipv4 ping
socket implementation in the Linux kernel. A local privileged attacker
could use this to cause a denial of service (system crash).
(CVE-2017-2671)

It was discovered that the freelist-randomization in the SLAB memory
allocator allowed duplicate freelist entries. A local attacker could
use this to cause a denial of service (system crash). (CVE-2017-5546)

It was discovered that the KLSI KL5KUSB105 serial-to-USB device driver
in the Linux kernel did not properly initialize memory related to
logging. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2017-5549)

It was discovered that a fencepost error existed in the pipe_advance()
function in the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2017-5550)

It was discovered that the Linux kernel did not clear the setgid bit
during a setxattr call on a tmpfs filesystem. A local attacker could
use this to gain elevated group privileges. (CVE-2017-5551)

Murray McAllister discovered that an integer overflow existed in the
VideoCore DRM driver of the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-5576)

Gareth Evans discovered that the shm IPC subsystem in the Linux kernel
did not properly restrict mapping page zero. A local privileged
attacker could use this to execute arbitrary code. (CVE-2017-5669)

Andrey Konovalov discovered an out-of-bounds access in the IPv6
Generic Routing Encapsulation (GRE) tunneling implementation in the
Linux kernel. An attacker could use this to possibly expose sensitive
information. (CVE-2017-5897)

Andrey Konovalov discovered that the IPv4 implementation in the Linux
kernel did not properly handle invalid IP options in some situations.
An attacker could use this to cause a denial of service or possibly
execute arbitrary code. (CVE-2017-5970)

Di Shen discovered that a race condition existed in the perf subsystem
of the Linux kernel. A local attacker could use this to cause a denial
of service or possibly gain administrative privileges. (CVE-2017-6001)

Dmitry Vyukov discovered that the Linux kernel did not properly handle
TCP packets with the URG flag. A remote attacker could use this to
cause a denial of service. (CVE-2017-6214)

Andrey Konovalov discovered that the LLC subsytem in the Linux kernel
did not properly set up a destructor in certain situations. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-6345)

It was discovered that a race condition existed in the AF_PACKET
handling code in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-6346)

Andrey Konovalov discovered that the IP layer in the Linux kernel made
improper assumptions about internal data layout when performing
checksums. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-6347)

Dmitry Vyukov discovered race conditions in the Infrared (IrDA)
subsystem in the Linux kernel. A local attacker could use this to
cause a denial of service (deadlock). (CVE-2017-6348)

Dmitry Vyukov discovered that the generic SCSI (sg) subsystem in the
Linux kernel contained a stack-based buffer overflow. A local attacker
with access to an sg device could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-7187)

It was discovered that a NULL pointer dereference existed in the
Direct Rendering Manager (DRM) driver for VMware devices in the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash). (CVE-2017-7261)

It was discovered that the USB Cypress HID drivers for the Linux
kernel did not properly validate reported information from the device.
An attacker with physical access could use this to expose sensitive
information (kernel memory). (CVE-2017-7273)

Eric Biggers discovered a memory leak in the keyring implementation in
the Linux kernel. A local attacker could use this to cause a denial of
service (memory consumption). (CVE-2017-7472)

It was discovered that an information leak existed in the
set_mempolicy and mbind compat syscalls in the Linux kernel. A local
attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-7616)

Sabrina Dubroca discovered that the asynchronous cryptographic hash
(ahash) implementation in the Linux kernel did not properly handle a
full request queue. A local attacker could use this to cause a denial
of service (infinite recursion). (CVE-2017-7618)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3
server implementations in the Linux kernel did not properly handle
certain long RPC replies. A remote attacker could use this to cause a
denial of service (system crash). (CVE-2017-7645)

Tommi Rantala and Brad Spengler discovered that the memory manager in
the Linux kernel did not properly enforce the CONFIG_STRICT_DEVMEM
protection mechanism. A local attacker with access to /dev/mem could
use this to expose sensitive information or possibly execute arbitrary
code. (CVE-2017-7889)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3
server implementations in the Linux kernel did not properly check for
the end of buffer. A remote attacker could use this to craft requests
that cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-7895)

It was discovered that an integer underflow existed in the Edgeport
USB Serial Converter device driver of the Linux kernel. An attacker
with physical access could use this to expose sensitive information
(kernel memory). (CVE-2017-8924)

It was discovered that the USB ZyXEL omni.net LCD PLUS driver in the
Linux kernel did not properly perform reference counting. A local
attacker could use this to cause a denial of service (tty exhaustion).
(CVE-2017-8925)

Jann Horn discovered that bpf in Linux kernel does not restrict the
output of the print_bpf_insn function. A local attacker could use this
to obtain sensitive address information. (CVE-2017-9150).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3361-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.10-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.10-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.10-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/24");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2015-1350", "CVE-2016-10208", "CVE-2016-8405", "CVE-2016-8636", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9191", "CVE-2016-9604", "CVE-2016-9755", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2618", "CVE-2017-2671", "CVE-2017-5546", "CVE-2017-5549", "CVE-2017-5550", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6348", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7472", "CVE-2017-7616", "CVE-2017-7618", "CVE-2017-7645", "CVE-2017-7889", "CVE-2017-7895", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9150");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3361-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.10.0-27-generic", pkgver:"4.10.0-27.30~16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.10.0-27-generic-lpae", pkgver:"4.10.0-27.30~16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.10.0-27-lowlatency", pkgver:"4.10.0-27.30~16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.10.0.27.30")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae-hwe-16.04", pkgver:"4.10.0.27.30")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.10.0.27.30")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.10-generic / linux-image-4.10-generic-lpae / etc");
}
