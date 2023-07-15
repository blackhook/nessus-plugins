#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1369-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109531);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-0861", "CVE-2017-13166", "CVE-2017-16526", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-18216", "CVE-2017-5715", "CVE-2018-1000004", "CVE-2018-1000199", "CVE-2018-1068", "CVE-2018-1092", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5750", "CVE-2018-5803", "CVE-2018-6927", "CVE-2018-7492", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Debian DLA-1369-1 : linux security update (Spectre)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-0861

Robb Glasser reported a potential use-after-free in the ALSA (sound)
PCM core. We believe this was not possible in practice.

CVE-2017-5715

Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes running
on the system.

This specific attack has been named Spectre variant 2
(branch target injection) and is mitigated for the x86
architecture (amd64 and i386) by using the 'retpoline'
compiler feature which allows indirect branches to be
isolated from speculative execution.

CVE-2017-13166

A bug in the 32-bit compatibility layer of the v4l2 ioctl handling
code has been found. Memory protections ensuring user-provided buffers
always point to userland memory were disabled, allowing destination
addresses to be in kernel space. On a 64-bit kernel (amd64 flavour) a
local user with access to a suitable video device can exploit this to
overwrite kernel memory, leading to privilege escalation.

CVE-2017-16526

Andrey Konovalov reported that the UWB subsystem may dereference an
invalid pointer in an error case. A local user might be able to use
this for denial of service.

CVE-2017-16911

Secunia Research reported that the USB/IP vhci_hcd driver exposed
kernel heap addresses to local users. This information could aid the
exploitation of other vulnerabilities.

CVE-2017-16912

Secunia Research reported that the USB/IP stub driver failed to
perform a range check on a received packet header field, leading to an
out-of-bounds read. A remote user able to connect to the USB/IP server
could use this for denial of service.

CVE-2017-16913

Secunia Research reported that the USB/IP stub driver failed to
perform a range check on a received packet header field, leading to
excessive memory allocation. A remote user able to connect to the
USB/IP server could use this for denial of service.

CVE-2017-16914

Secunia Research reported that the USB/IP stub driver failed to check
for an invalid combination of fields in a recieved packet, leading to
a NULL pointer dereference. A remote user able to connect to the
USB/IP server could use this for denial of service.

CVE-2017-18017

Denys Fedoryshchenko reported that the netfilter xt_TCPMSS module
failed to validate TCP header lengths, potentially leading to a
use-after-free. If this module is loaded, it could be used by a remote
attacker for denial of service or possibly for code execution.

CVE-2017-18203

Hou Tao reported that there was a race condition in creation and
deletion of device-mapper (DM) devices. A local user could potentially
use this for denial of service.

CVE-2017-18216

Alex Chen reported that the OCFS2 filesystem failed to hold a
necessary lock during nodemanager sysfs file operations, potentially
leading to a NULL pointer dereference. A local user could use this for
denial of service.

CVE-2018-1068

The syzkaller tool found that the 32-bit compatibility layer of
ebtables did not sufficiently validate offset values. On a 64-bit
kernel (amd64 flavour), a local user with the CAP_NET_ADMIN capability
could use this to overwrite kernel memory, possibly leading to
privilege escalation.

CVE-2018-1092

Wen Xu reported that a crafted ext4 filesystem image would trigger a
null dereference when mounted. A local user able to mount arbitrary
filesystems could use this for denial of service.

CVE-2018-5332

Mohamed Ghannam reported that the RDS protocol did not sufficiently
validate RDMA requests, leading to an out-of-bounds write. A local
attacker on a system with the rds module loaded could use this for
denial of service or possibly for privilege escalation.

CVE-2018-5333

Mohamed Ghannam reported that the RDS protocol did not properly handle
an error case, leading to a NULL pointer dereference. A local attacker
on a system with the rds module loaded could possibly use this for
denial of service.

CVE-2018-5750

Wang Qize reported that the ACPI sbshc driver logged a kernel heap
address. This information could aid the exploitation of other
vulnerabilities.

CVE-2018-5803

Alexey Kodanev reported that the SCTP protocol did not range-check the
length of chunks to be created. A local or remote user could use this
to cause a denial of service.

CVE-2018-6927

Li Jinyue reported that the FUTEX_REQUEUE operation on futexes did not
check for negative parameter values, which might lead to a denial of
service or other security impact.

CVE-2018-7492

The syzkaller tool found that the RDS protocol was lacking a NULL pointer check. A local attacker on a system with the rds module loaded
could use this for denial of service.

CVE-2018-7566

&#x8303;&#x9F99;&#x98DE; (Fan LongFei) reported a race condition in
the ALSA (sound) sequencer core, between write and ioctl operations.
This could lead to an out-of-bounds access or use-after-free. A local
user with access to a sequencer device could use this for denial of
service or possibly for privilege escalation.

CVE-2018-7740

Nic Losby reported that the hugetlbfs filesystem's mmap operation did
not properly range-check the file offset. A local user with access to
files on a hugetlbfs filesystem could use this to cause a denial of
service.

CVE-2018-7757

Jason Yan reported a memory leak in the SAS (Serial-Attached SCSI)
subsystem. A local user on a system with SAS devices could use this to
cause a denial of service.

CVE-2018-7995

Seunghun Han reported a race condition in the x86 MCE (Machine Check
Exception) driver. This is unlikely to have any security impact.

CVE-2018-8781

Eyal Itkin reported that the udl (DisplayLink) driver's mmap operation
did not properly range-check the file offset. A local user with access
to a udl framebuffer device could exploit this to overwrite kernel
memory, leading to privilege escalation.

CVE-2018-8822

Dr Silvio Cesare of InfoSect reported that the ncpfs client
implementation did not validate reply lengths from the server. An
ncpfs server could use this to cause a denial of service or remote
code execution in the client.

CVE-2018-1000004

Luo Quan reported a race condition in the ALSA (sound) sequencer core,
between multiple ioctl operations. This could lead to a deadlock or
use-after-free. A local user with access to a sequencer device could
use this for denial of service or possibly for privilege escalation.

CVE-2018-1000199

Andy Lutomirski discovered that the ptrace subsystem did not
sufficiently validate hardware breakpoint settings. Local users can
use this to cause a denial of service, or possibly for privilege
escalation, on x86 (amd64 and i386) and possibly other architectures.

Additionally, some mitigations for CVE-2017-5753 are included in this
release :

CVE-2017-5753

Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes running
on the system.

This specific attack has been named Spectre variant 1
(bounds-check bypass) and is mitigated by identifying
vulnerable code sections (array bounds checking followed by
array access) and replacing the array access with the
speculation-safe array_index_nospec() function.

More use sites will be added over time.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.101-1. This version also includes bug fixes from upstream versions
up to and including 3.2.101. It also fixes a regression in the procfs
hidepid option in the previous version (Debian bug #887106).

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/05/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/linux"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-486");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-ia64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-mipsel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-powerpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-all-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-iop32x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-itanium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-ixp4xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-kirkwood");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-loongson-2f");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-mckinley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-mv78xx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-mx5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-omap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-orion5x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-powerpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-powerpc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-r4k-ip22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-r5k-cobalt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-r5k-ip32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-sb1-bcm91250a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-sb1a-bcm91480b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-sparc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-sparc64-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-3.2.0-4-vexpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-486");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-iop32x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-itanium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-ixp4xx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-kirkwood");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-loongson-2f");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-mckinley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-mv78xx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-mx5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-omap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-orion5x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-powerpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-powerpc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-r4k-ip22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-r5k-cobalt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-r5k-ip32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-s390x-tape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-sb1-bcm91250a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-sb1a-bcm91480b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-sparc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-sparc64-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-3.2.0-4-vexpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-3.2.0-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-3.2.0-4-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-3.2.0-4-amd64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");

# Temp disable
exit(1, "Temporarily disabled.");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"linux-doc-3.2", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-486", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-4kc-malta", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-5kc-malta", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-686-pae", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-amd64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-armel", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-armhf", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-i386", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-ia64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-mips", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-mipsel", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-powerpc", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-s390", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-s390x", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-sparc", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-amd64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-common", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-common-rt", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-iop32x", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-itanium", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-ixp4xx", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-kirkwood", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-loongson-2f", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mckinley", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mv78xx0", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mx5", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-octeon", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-omap", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-orion5x", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc-smp", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r4k-ip22", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r5k-cobalt", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r5k-ip32", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-rt-686-pae", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-rt-amd64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-s390x", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sb1-bcm91250a", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sb1a-bcm91480b", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sparc64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sparc64-smp", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-versatile", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-vexpress", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-486", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-4kc-malta", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-5kc-malta", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-686-pae", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-686-pae-dbg", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-amd64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-amd64-dbg", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-iop32x", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-itanium", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-ixp4xx", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-kirkwood", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-loongson-2f", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mckinley", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mv78xx0", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mx5", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-octeon", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-omap", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-orion5x", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc-smp", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r4k-ip22", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r5k-cobalt", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r5k-ip32", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-686-pae", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-686-pae-dbg", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-amd64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-amd64-dbg", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x-dbg", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x-tape", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sb1-bcm91250a", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sb1a-bcm91480b", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sparc64", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sparc64-smp", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-versatile", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-vexpress", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-libc-dev", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-manual-3.2", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-source-3.2", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"linux-support-3.2.0-4", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-linux-system-3.2.0-4-686-pae", reference:"3.2.101-1")) flag++;
if (deb_check(release:"7.0", prefix:"xen-linux-system-3.2.0-4-amd64", reference:"3.2.101-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
