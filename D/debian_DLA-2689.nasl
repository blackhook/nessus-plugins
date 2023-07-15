#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2689-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(150985);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-26139", "CVE-2020-26147", "CVE-2020-26558", "CVE-2020-29374", "CVE-2020-36322", "CVE-2021-0129", "CVE-2021-20292", "CVE-2021-23133", "CVE-2021-23134", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28950", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-29154", "CVE-2021-29265", "CVE-2021-29647", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-31916", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-3428", "CVE-2021-3483", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-3587");

  script_name(english:"Debian DLA-2689-1 : linux security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to the execution of arbitrary code, privilege escalation,
denial of service, or information leaks.

This update is not yet available for the armel (ARM EABI soft-float)
architecture.

CVE-2020-24586, CVE-2020-24587, CVE-2020-26147

Mathy Vanhoef discovered that many Wi-Fi implementations, including
Linux's mac80211, did not correctly implement reassembly of fragmented
packets. In some circumstances, an attacker within range of a network
could exploit these flaws to forge arbitrary packets and/or to access
sensitive data on that network.

CVE-2020-24588

Mathy Vanhoef discovered that most Wi-Fi implementations, including
Linux's mac80211, did not authenticate the 'is aggregated' packet
header flag. An attacker within range of a network could exploit this
to forge arbitrary packets on that network.

CVE-2020-25670, CVE-2020-25671, CVE-2021-23134

kiyin (&#x5C39;&#x4EAE;) of TenCent discovered several reference
counting bugs in the NFC LLCP implementation which could lead to
use-after-free. A local user could exploit these for denial of service
(crash or memory corruption) or possibly for privilege escalation.

Nadav Markus and Or Cohen of Palo Alto Networks discovered
that the original fixes for these introduced a new bug that
could result in use-after-free and double-free. This has
also been fixed.

CVE-2020-25672

kiyin (&#x5C39;&#x4EAE;) of TenCent discovered a memory leak in the
NFC LLCP implementation. A local user could exploit this for denial of
service (memory exhaustion).

CVE-2020-26139

Mathy Vanhoef discovered that a bug in some Wi-Fi implementations,
including Linux's mac80211. When operating in AP mode, they would
forward EAPOL frames from one client to another while the sender was
not yet authenticated. An attacker within range of a network could use
this for denial of service or as an aid to exploiting other
vulnerabilities.

CVE-2020-26558, CVE-2021-0129

Researchers at ANSSI discovered vulnerabilities in the Bluetooth
Passkey authentication method, and in Linux's implementation of it. An
attacker within range of two Bluetooth devices while they pair using
Passkey authentication could exploit this to obtain the shared secret
(Passkey) and then impersonate either of the devices to each other.

CVE-2020-29374

Jann Horn of Google reported a flaw in Linux's virtual memory
management. A parent and child process initially share all their
memory, but when either writes to a shared page, the page is
duplicated and unshared (copy-on-write). However, in case an operation
such as vmsplice() required the kernel to take an additional reference
to a shared page, and a copy-on-write occurs during this operation,
the kernel might have accessed the wrong process's memory. For some
programs, this could lead to an information leak or data corruption.

CVE-2020-36322, CVE-2021-28950

The syzbot tool found that the FUSE (filesystem-in-user-space)
implementation did not correctly handle a FUSE server returning
invalid attributes for a file. A local user permitted to run a FUSE
server could use this to cause a denial of service (crash).

The original fix for this introduced a different potential
denial of service (infinite loop in kernel space), which has
also been fixed.

CVE-2021-3428

Wolfgang Frisch reported a potential integer overflow in the ext4
filesystem driver. A user permitted to mount arbitrary filesystem
images could use this to cause a denial of service (crash).

CVE-2021-3483

&#x9A6C;&#x54F2;&#x5B87; (Zheyu Ma) reported a bug in the 'nosy'
driver for TI PCILynx FireWire controllers, which could lead to list
corruption and a use-after-free. On a system that uses this driver,
local users granted access to /dev/nosy could exploit this to cause a
denial of service (crash or memory corruption) or possibly for
privilege escalation.

CVE-2021-3564, CVE-2021-3573, CVE-2021-32399

The BlockSec team discovered several race conditions in the Bluetooth
subsystem that could lead to a use-after-free or double-free. A local
user could exploit these to caue a denial of service (crash or memory
corruption) or possibly for privilege escalation.

CVE-2021-3587

Active Defense Lab of Venustech discovered a potential NULL pointer
dereference in the NFC LLCP implementation. A local user could use
this to cause a denial of service (crash).

CVE-2021-20292

It was discovered that the TTM buffer allocation API used by GPU
drivers did not handle allocation failures in the way that most
drivers expected, resulting in a double-free on failure. A local user
on a system using one of these drivers could possibly exploit this to
cause a denial of service (crash or memory corruption) or for
privilege escalation. The API has been changed to match driver
expectations.

CVE-2021-23133

Or Cohen of Palo Alto Networks discovered a race condition in the SCTP
implementation, which can lead to list corruption. A local user could
exploit this to cause a denial of service (crash or memory corruption)
or possibly for privilege escalation.

CVE-2021-28660

It was discovered that the rtl8188eu WiFi driver did not correctly
limit the length of SSIDs copied into scan results. An attacker within
WiFi range could use this to cause a denial of service (crash or
memory corruption) or possibly to execute code on a vulnerable system.

CVE-2021-28688 (XSA-371)

It was discovered that the original fix for CVE-2021-26930 (XSA-365)
introduced a potential resource leak. A malicious guest could
presumably exploit this to cause a denial of service (resource
exhaustion) within the host.

CVE-2021-28964

Zygo Blaxell reported a race condition in the Btrfs driver which can
lead to an assertion failure. On systems using Btrfs, a local user
could exploit this to cause a denial of service (crash).

CVE-2021-28971

Vince Weaver reported a bug in the performance event handler for Intel
PEBS. A workaround for a hardware bug on Intel CPUs codenamed
'Haswell' and earlier could lead to a NULL pointer dereference. On
systems with the affected CPUs, if users are permitted to access
performance events, a local user may exploit this to cause a denial of
service (crash).

By default, unprivileged users do not have access to
performance events, which mitigates this issue. This is
controlled by the kernel.perf_event_paranoid sysctl.

CVE-2021-29154

It was discovered that the Extended BPF (eBPF) JIT compiler for x86_64
generated incorrect branch instructions in some cases. On systems
where eBPF JIT is enabled, users could exploit this to execute
arbitrary code in the kernel.

By default, eBPF JIT is disabled, mitigating this issue.
This is controlled by the net.core.bpf_jit_enable sysctl.

CVE-2021-29265

The syzbot tool found a race condition in the USB/IP host (server)
implementation which can lead to a NULL pointer dereference. On a
system acting as a USB/IP host, a client can exploit this to cause a
denial of service (crash).

CVE-2021-29647

The syzbot tool found an information leak in the Qualcomm IPC Router
(qrtr) implementation.

This protocol is not enabled in Debian's official kernel
configurations.

CVE-2021-29650

It was discovered that a data race in the netfilter subsystem could
lead to a NULL pointer dereference during replacement of a table. A
local user with CAP_NET_ADMIN capability in any user namespace could
use this to cause a denial of service (crash).

By default, unprivileged users cannot create user
namespaces, which mitigates this issue. This is controlled
by the kernel.unprivileged_userns_clone sysctl.

CVE-2021-30002

Arnd Bergmann and the syzbot tool found a memory leak in the
Video4Linux (v4l) subsystem. A local user permitted to access video
devices (by default, any member of the 'video' group) could exploit
this to cause a denial of service (memory exhaustion).

CVE-2021-31916

Dan Carpenter reported incorrect parameter validation in the
device-mapper (dm) subsystem, which could lead to a heap buffer
overrun. However, only users with CAP_SYS_ADMIN capability (i.e.
root-equivalent) could trigger this bug, so it did not have any
security impact in this kernel version.

CVE-2021-33034

The syzbot tool found a bug in the Bluetooth subsystem that could lead
to a use-after-free. A local user could use this to cause a denial of
service (crash or memory corruption) or possibly for privilege
escalation.

For Debian 9 stretch, these problems have been fixed in version
4.9.272-1. This update additionally includes many more bug fixes from
stable updates 4.9.259-4.9.272 inclusive.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/linux

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libusbip-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-6-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-6-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-mips64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-mipsel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-ppc64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-all-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-9-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-9-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.9.0-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.272-1")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.272-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
