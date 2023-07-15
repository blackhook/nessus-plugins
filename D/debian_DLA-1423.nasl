#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1423-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111165);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-18255", "CVE-2017-5753", "CVE-2018-1000204", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-10853", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-10940", "CVE-2018-1118", "CVE-2018-1120", "CVE-2018-1130", "CVE-2018-11506", "CVE-2018-12233", "CVE-2018-3639", "CVE-2018-5814");

  script_name(english:"Debian DLA-1423-1 : linux-4.9 new package (Spectre)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Linux 4.9 has been packaged for Debian 8 as linux-4.9. This provides a
supported upgrade path for systems that currently use kernel packages
from the 'jessie-backports' suite.

There is no need to upgrade systems using Linux 3.16, as that kernel
version will also continue to be supported in the LTS period.

This backport does not include the following binary packages :

hyperv-daemons libcpupower1 libcpupower-dev libusbip-dev
linux-compiler-gcc-4.9-x86 linux-cpupower linux-libc-dev usbip

Older versions of most of those are built from other source packages
in Debian 8.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-5753

Further instances of code that was vulnerable to Spectre variant 1
(bounds-check bypass) have been mitigated.

CVE-2017-18255

It was discovered that the performance events subsystem did not
properly validate the value of the kernel.perf_cpu_time_max_percent
sysctl. Setting a large value could have an unspecified security
impact. However, only a privileged user can set this sysctl.

CVE-2018-1118

The syzbot software found that the vhost driver did not initialise
message buffers which would later be read by user processes. A user
with access to the /dev/vhost-net device could use this to read
sensitive information from the kernel or other users' processes.

CVE-2018-1120

Qualys reported that a user able to mount FUSE filesystems can create
a process such that when another process attempting to read its
command line will be blocked for an arbitrarily long time. This could
be used for denial of service, or to aid in exploiting a race
condition in the other program.

CVE-2018-1130

The syzbot software found that the DCCP implementation of sendmsg()
does not check the socket state, potentially leading to a NULL pointer
dereference. A local user could use this to cause a denial of service
(crash). 

CVE-2018-3639

Multiple researchers have discovered that Speculative Store Bypass
(SSB), a feature implemented in many processors, could be used to read
sensitive information from another context. In particular, code in a
software sandbox may be able to read sensitive information from
outside the sandbox. This issue is also known as Spectre variant 4.

This update allows the issue to be mitigated on some x86
processors by disabling SSB. This requires an update to the
processor's microcode, which is non-free. It may be included
in an update to the system BIOS or UEFI firmware, or in a
future update to the intel-microcode or amd64-microcode
packages.

Disabling SSB can reduce performance significantly, so by
default it is only done in tasks that use the seccomp
feature. Applications that require this mitigation should
request it explicitly through the prctl() system call. Users
can control where the mitigation is enabled with the
spec_store_bypass_disable kernel parameter.

CVE-2018-5814

Jakub Jirasek reported race conditions in the USB/IP host driver. A
malicious client could use this to cause a denial of service (crash or
memory corruption), and possibly to execute code, on a USB/IP server.

CVE-2018-10021

A physically present attacker who unplugs a SAS cable can cause a
denial of service (memory leak and WARN).

CVE-2018-10087, CVE-2018-10124

zhongjiang found that the wait4() and kill() system call
implementations did not check for the invalid pid value of INT_MIN. If
a user passed this value, the behaviour of the code was formally
undefined and might have had a security impact.

CVE-2018-10853

Andy Lutomirski and Mika Penttil&auml; reported that KVM for x86
processors did not perform a necessary privilege check when emulating
certain instructions. This could be used by an unprivileged user in a
guest VM to escalate their privileges within the guest.

CVE-2018-10876, CVE-2018-10877, CVE-2018-10878, CVE-2018-10879,
CVE-2018-10880, CVE-2018-10881, CVE-2018-10882, CVE-2018-10883

Wen Xu at SSLab, Gatech, reported that crafted ext4 filesystem images
could trigger a crash or memory corruption. A local user able to mount
arbitrary filesystems, or an attacker providing filesystems to be
mounted, could use this for denial of service or possibly for
privilege escalation.

CVE-2018-10940

Dan Carpenter reported that the optical disc driver (cdrom) does not
correctly validate the parameter to the CDROM_MEDIA_CHANGED ioctl. A
user with access to a cdrom device could use this to cause a denial of
service (crash).

CVE-2018-11506

Piotr Gabriel Kosinski and Daniel Shapira reported that the SCSI
optical disc driver (sr) did not allocate a sufficiently large buffer
for sense data. A user with access to a SCSI optical disc device that
can produce more than 64 bytes of sense data could use this to cause a
denial of service (crash or memory corruption), and possibly for
privilege escalation.

CVE-2018-12233

Shankara Pailoor reported that a crafted JFS filesystem image could
trigger a denial of service (memory corruption). This could possibly
also be used for privilege escalation.

CVE-2018-1000204

The syzbot software found that the SCSI generic driver (sg) would in
some circumstances allow reading data from uninitialised buffers,
which could include sensitive information from the kernel or other
tasks. However, only privileged users with the CAP_SYS_ADMIN or
CAP_SYS_RAWIO capability were allowed to do this, so this has little
or no security impact.

For Debian 8 'Jessie', these problems have been fixed in version
4.9.110-1~deb8u1. This update additionally fixes Debian bugs #860900,
#872907, #892057, #896775, #897590, and #898137; and includes many
more bug fixes from stable updates 4.9.89-4.9.110 inclusive.

We recommend that you upgrade your linux-4.9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux-4.9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.9-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.9.0-0.bpo.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-arm", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-4.9", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686-pae", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-amd64", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armel", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armhf", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-i386", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-amd64", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common-rt", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-marvell", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64-dbg", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-marvell", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-kbuild-4.9", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-4.9", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-perf-4.9", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-4.9", reference:"4.9.110-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-4.9.0-0.bpo.7", reference:"4.9.110-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
