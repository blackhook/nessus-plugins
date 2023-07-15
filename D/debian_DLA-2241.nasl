#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2241-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137283);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-8839", "CVE-2018-14610", "CVE-2018-14611", "CVE-2018-14612", "CVE-2018-14613", "CVE-2019-19319", "CVE-2019-19447", "CVE-2019-19768", "CVE-2019-20636", "CVE-2019-5108", "CVE-2020-0009", "CVE-2020-0543", "CVE-2020-10690", "CVE-2020-10751", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12769", "CVE-2020-12770", "CVE-2020-12826", "CVE-2020-13143", "CVE-2020-1749", "CVE-2020-2732", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383");

  script_name(english:"Debian DLA-2241-2 : linux security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update is now available for all supported architectures. For
reference the original advisory text follows.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2015-8839

A race condition was found in the ext4 filesystem implementation. A
local user could exploit this to cause a denial of service (filesystem
corruption).

CVE-2018-14610, CVE-2018-14611, CVE-2018-14612, CVE-2018-14613

Wen Xu from SSLab at Gatech reported that crafted Btrfs volumes could
trigger a crash (Oops) and/or out-of-bounds memory access. An attacker
able to mount such a volume could use this to cause a denial of
service or possibly for privilege escalation.

CVE-2019-5108

Mitchell Frank of Cisco discovered that when the IEEE 802.11 (WiFi)
stack was used in AP mode with roaming, it would trigger roaming for a
newly associated station before the station was authenticated. An
attacker within range of the AP could use this to cause a denial of
service, either by filling up a switching table or by redirecting
traffic away from other stations.

CVE-2019-19319

Jungyeon discovered that a crafted filesystem can cause the ext4
implementation to deallocate or reallocate journal blocks. A user
permitted to mount filesystems could use this to cause a denial of
service (crash), or possibly for privilege escalation.

CVE-2019-19447

It was discovered that the ext4 filesystem driver did not safely
handle unlinking of an inode that, due to filesystem corruption,
already has a link count of 0. An attacker able to mount arbitrary
ext4 volumes could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

CVE-2019-19768

Tristan Madani reported a race condition in the blktrace debug
facility that could result in a use-after-free. A local user able to
trigger removal of block devices could possibly use this to cause a
denial of service (crash) or for privilege escalation.

CVE-2019-20636

The syzbot tool found that the input subsystem did not fully validate
keycode changes, which could result in a heap out-of-bounds write. A
local user permitted to access the device node for an input or VT
device could possibly use this to cause a denial of service (crash or
memory corruption) or for privilege escalation.

CVE-2020-0009

Jann Horn reported that the Android ashmem driver did not prevent
read-only files from being memory-mapped and then remapped as
read-write. However, Android drivers are not enabled in Debian kernel
configurations.

CVE-2020-0543

Researchers at VU Amsterdam discovered that on some Intel CPUs
supporting the RDRAND and RDSEED instructions, part of a random value
generated by these instructions may be used in a later speculative
execution on any core of the same physical CPU. Depending on how these
instructions are used by applications, a local user or VM guest could
use this to obtain sensitive information such as cryptographic keys
from other users or VMs.

This vulnerability can be mitigated by a microcode update,
either as part of system firmware (BIOS) or through the
intel-microcode package in Debian's non-free archive
section. This kernel update only provides reporting of the
vulnerability and the option to disable the mitigation if it
is not needed.

CVE-2020-1749

Xiumei Mu reported that some network protocols that can run on top of
IPv6 would bypass the Transformation (XFRM) layer used by IPsec,
IPcomp/IPcomp6, IPIP, and IPv6 Mobility. This could result in
disclosure of information over the network, since it would not be
encrypted or routed according to the system policy.

CVE-2020-2732

Paulo Bonzini discovered that the KVM implementation for Intel
processors did not properly handle instruction emulation for L2 guests
when nested virtualization is enabled. This could allow an L2 guest to
cause privilege escalation, denial of service, or information leaks in
the L1 guest.

CVE-2020-8647, CVE-2020-8649

The Hulk Robot tool found a potential MMIO out-of-bounds access in the
vgacon driver. A local user permitted to access a virtual terminal
(/dev/tty1 etc.) on a system using the vgacon driver could use this to
cause a denial of service (crash or memory corruption) or possibly for
privilege escalation.

CVE-2020-8648

The syzbot tool found a race condition in the the virtual terminal
driver, which could result in a use-after-free. A local user permitted
to access a virtual terminal could use this to cause a denial of
service (crash or memory corruption) or possibly for privilege
escalation.

CVE-2020-9383

Jordy Zomer reported an incorrect range check in the floppy driver
which could lead to a static out-of-bounds access. A local user
permitted to access a floppy drive could use this to cause a denial of
service (crash or memory corruption) or possibly for privilege
escalation.

CVE-2020-10690

It was discovered that the PTP hardware clock subsystem did not
properly manage device lifetimes. Removing a PTP hardware clock from
the system while a user process was using it could lead to a
use-after-free. The security impact of this is unclear.

CVE-2020-10751

Dmitry Vyukov reported that the SELinux subsystem did not properly
handle validating multiple messages, which could allow a privileged
attacker to bypass SELinux netlink restrictions.

CVE-2020-10942

It was discovered that the vhost_net driver did not properly validate
the type of sockets set as back-ends. A local user permitted to access
/dev/vhost-net could use this to cause a stack corruption via crafted
system calls, resulting in denial of service (crash) or possibly
privilege escalation.

CVE-2020-11494

It was discovered that the slcan (serial line CAN) network driver did
not fully initialise CAN headers for received packets, resulting in an
information leak from the kernel to user-space or over the CAN
network.

CVE-2020-11565

Entropy Moe reported that the shared memory filesystem (tmpfs) did not
correctly handle an 'mpol' mount option specifying an empty node list,
leading to a stack-based out-of-bounds write. If user namespaces are
enabled, a local user could use this to cause a denial of service
(crash) or possibly for privilege escalation.

CVE-2020-11608, CVE-2020-11609, CVE-2020-11668

It was discovered that the ov519, stv06xx, and xirlink_cit media
drivers did not properly validate USB device descriptors. A physically
present user with a specially constructed USB device could use this to
cause a denial of service (crash) or possibly for privilege
escalation.

CVE-2020-12114

Piotr Krysiuk discovered a race condition between the umount and
pivot_root operations in the filesystem core (vfs). A local user with
the CAP_SYS_ADMIN capability in any user namespace could use this to
cause a denial of service (crash).

CVE-2020-12464

Kyungtae Kim reported a race condition in the USB core that can result
in a use-after-free. It is not clear how this can be exploited, but it
could result in a denial of service (crash or memory corruption) or
privilege escalation.

CVE-2020-12652

Tom Hatskevich reported a bug in the mptfusion storage drivers. An
ioctl handler fetched a parameter from user memory twice, creating a
race condition which could result in incorrect locking of internal
data structures. A local user permitted to access /dev/mptctl could
use this to cause a denial of service (crash or memory corruption) or
for privilege escalation.

CVE-2020-12653

It was discovered that the mwifiex WiFi driver did not sufficiently
validate scan requests, resulting a potential heap buffer overflow. A
local user with CAP_NET_ADMIN capability could use this to cause a
denial of service (crash or memory corruption) or possibly for
privilege escalation.

CVE-2020-12654

It was discovered that the mwifiex WiFi driver did not sufficiently
validate WMM parameters received from an access point (AP), resulting
a potential heap buffer overflow. A malicious AP could use this to
cause a denial of service (crash or memory corruption) or possibly to
execute code on a vulnerable system.

CVE-2020-12769

It was discovered that the spi-dw SPI host driver did not properly
serialise access to its internal state. The security impact of this is
unclear, and this driver is not included in Debian's binary packages.

CVE-2020-12770

It was discovered that the sg (SCSI generic) driver did not correctly
release internal resources in a particular error case. A local user
permitted to access an sg device could possibly use this to cause a
denial of service (resource exhaustion).

CVE-2020-12826

Adam Zabrocki reported a weakness in the signal subsystem's permission
checks. A parent process can choose an arbitary signal for a child
process to send when it exits, but if the parent has executed a new
program then the default SIGCHLD signal is sent. A local user
permitted to run a program for several days could bypass this check,
execute a setuid program, and then send an arbitrary signal to it.
Depending on the setuid programs installed, this could have some
security impact.

CVE-2020-13143

Kyungtae Kim reported a potential heap out-of-bounds write in the USB
gadget subsystem. A local user permitted to write to the gadget
configuration filesystem could use this to cause a denial of service
(crash or memory corruption) or potentially for privilege escalation.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.84-1.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12464");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.9-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-3.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-586");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-ixp4xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-kirkwood");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-orion5x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.16.0-9-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-586");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-ixp4xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-kirkwood");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-orion5x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.16.0-9-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-3.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-3.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-3.16.0-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-3.16.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.84-1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.84-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");