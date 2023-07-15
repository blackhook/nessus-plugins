#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2385-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140933);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2019-19448", "CVE-2019-19813", "CVE-2019-19816", "CVE-2019-3874", "CVE-2020-10781", "CVE-2020-12888", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14385", "CVE-2020-14386", "CVE-2020-14390", "CVE-2020-16166", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-26088");

  script_name(english:"Debian DLA-2385-1 : linux-4.19 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service, or information
leak.

CVE-2019-3874

Kernel buffers allocated by the SCTP network protocol were not limited
by the memory cgroup controller. A local user could potentially use
this to evade container memory limits and to cause a denial of service
(excessive memory use).

CVE-2019-19448, CVE-2019-19813, CVE-2019-19816

'Team bobfuzzer' reported bugs in Btrfs that could lead to a
use-after-free or heap buffer overflow, and could be triggered by
crafted filesystem images. A user permitted to mount and access
arbitrary filesystems could use these to cause a denial of service
(crash or memory corruption) or possibly for privilege escalation.

CVE-2020-10781

Luca Bruno of Red Hat discovered that the zram control file
/sys/class/zram-control/hot_add was readable by all users. On a system
with zram enabled, a local user could use this to cause a denial of
service (memory exhaustion).

CVE-2020-12888

It was discovered that the PCIe Virtual Function I/O (vfio-pci) driver
allowed users to disable a device's memory space while it was still
mapped into a process. On some hardware platforms, local users or
guest virtual machines permitted to access PCIe Virtual Functions
could use this to cause a denial of service (hardware error and
crash).

CVE-2020-14314

A bug was discovered in the ext4 filesystem that could lead to an
out-of-bound read. A local user permitted to mount and access
arbitrary filesystem images could use this to cause a denial of
service (crash).

CVE-2020-14331

A bug was discovered in the VGA console driver's soft-scrollback
feature that could lead to a heap buffer overflow. On a system with a
custom kernel that has CONFIG_VGACON_SOFT_SCROLLBACK enabled, a local
user with access to a console could use this to cause a denial of
service (crash or memory corruption) or possibly for privilege
escalation.

CVE-2020-14356

A bug was discovered in the cgroup subsystem's handling of socket
references to cgroups. In some cgroup configurations, this could lead
to a use-after-free. A local user might be able to use this to cause a
denial of service (crash or memory corruption) or possibly for
privilege escalation.

CVE-2020-14385

A bug was discovered in XFS, which could lead to an extended attribute
(xattr) wrongly being detected as invalid. A local user with access to
an XFS filesystem could use this to cause a denial of service
(filesystem shutdown).

CVE-2020-14386

Or Cohen discovered a bug in the packet socket (AF_PACKET)
implementation which could lead to a heap buffer overflow. A local
user with the CAP_NET_RAW capability (in any user namespace) could use
this to cause a denial of service (crash or memory corruption) or
possibly for privilege escalation.

CVE-2020-14390

Minh Yuan discovered a bug in the framebuffer console driver's
scrollback feature that could lead to a heap buffer overflow. On a
system using framebuffer consoles, a local user with access to a
console could use this to cause a denial of service (crash or memory
corruption) or possibly for privilege escalation.

The scrollback feature has been disabled for now, as no
other fix was available for this issue.

CVE-2020-16166

Amit Klein reported that the random number generator used by the
network stack might not be re-seeded for long periods of time, making
e.g. client port number allocations more predictable. This made it
easier for remote attackers to carry out some network- based attacks
such as DNS cache poisoning or device tracking.

CVE-2020-25212

A bug was discovered in the NFSv4 client implementation that could
lead to a heap buffer overflow. A malicious NFS server could use this
to cause a denial of service (crash or memory corruption) or possibly
to execute arbitrary code on the client.

CVE-2020-25284

It was discovered that the Rados block device (rbd) driver allowed
tasks running as uid 0 to add and remove rbd devices, even if they
dropped capabilities. On a system with the rbd driver loaded, this
might allow privilege escalation from a container with a task running
as root.

CVE-2020-25285

A race condition was discovered in the hugetlb filesystem's sysctl
handlers, that could lead to stack corruption. A local user permitted
to write to hugepages sysctls could use this to cause a denial of
service (crash or memory corruption) or possibly for privilege
escalation. By default only the root user can do this.

CVE-2020-25641

The syzbot tool found a bug in the block layer that could lead to an
infinite loop. A local user with access to a raw block device could
use this to cause a denial of service (unbounded CPU use and possible
system hang).

CVE-2020-26088

It was discovered that the NFC (Near Field Communication) socket
implementation allowed any user to create raw sockets. On a system
with an NFC interface, this allowed local users to evade local network
security policy.

For Debian 9 stretch, these problems have been fixed in version
4.19.146-1~deb9u1. This update additionally fixes Debian bugs #966846,
#966917, and #968567; and includes many more bug fixes from stable
updates 4.19.133-4.19.146 inclusive.

We recommend that you upgrade your linux-4.19 packages.

For the detailed security status of linux-4.19 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/linux-4.19

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux-4.19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux-4.19"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19816");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"linux-config-4.19", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.19", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686-pae", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-amd64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-arm64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armel", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armhf", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-i386", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-amd64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-arm64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common-rt", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-marvell", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rpi", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp-dbg", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.19", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.19", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.19", reference:"4.19.146-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.19.0-0.bpo.10", reference:"4.19.146-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
