#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1422-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111082);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000204", "CVE-2018-1066", "CVE-2018-10853", "CVE-2018-1093", "CVE-2018-10940", "CVE-2018-1130", "CVE-2018-11506", "CVE-2018-12233", "CVE-2018-3665", "CVE-2018-5814", "CVE-2018-9422");

  script_name(english:"Debian DLA-1422-2 : linux security update (Spectre)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The previous update to linux failed to build for the armhf (ARM EABI
hard-float) architecture. This update corrects that. For all other
architectures, there is no need to upgrade or reboot again. For
reference, the relevant part of the original advisory text follows.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-5715

Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes running
on the system.

This specific attack has been named Spectre variant 2
(branch target injection) and is mitigated for the x86
architecture (amd64 and i386) by using new microcoded
features.

This mitigation requires an update to the processor's
microcode, which is non-free. For recent Intel processors,
this is included in the intel-microcode package from version
3.20180425.1~deb8u1. For other processors, it may be
included in an update to the system BIOS or UEFI firmware,
or in a later update to the amd64-microcode package.

This vulnerability was already mitigated for the x86
architecture by the 'retpoline' feature.

CVE-2017-5753

Further instances of code that was vulnerable to Spectre variant 1
(bounds-check bypass) have been mitigated.

CVE-2018-1066

Dan Aloni reported to Red Hat that the CIFS client implementation
would dereference a NULL pointer if the server sent an invalid
response during NTLMSSP setup negotiation. This could be used by a
malicious server for denial of service.

The previously applied mitigation for this issue was not
appropriate for Linux 3.16 and has been replaced by an
alternate fix.

CVE-2018-1093

Wen Xu reported that a crafted ext4 filesystem image could trigger an
out-of-bounds read in the ext4_valid_block_bitmap() function. A local
user able to mount arbitrary filesystems could use this for denial of
service.

CVE-2018-1130

The syzbot software found that the DCCP implementation of sendmsg()
does not check the socket state, potentially leading to a NULL pointer
dereference. A local user could use this to cause a denial of service
(crash). 

CVE-2018-3665

Multiple researchers have discovered that some Intel x86 processors
can speculatively read floating-point and vector registers even when
access to those registers is disabled. The Linux kernel's 'lazy FPU'
feature relies on that access control to avoid saving and restoring
those registers for tasks that do not use them, and was enabled by
default on x86 processors that do not support the XSAVEOPT
instruction.

If 'lazy FPU' is enabled on one of the affected processors,
an attacker controlling an unprivileged process may be able
to read sensitive information from other users' processes or
the kernel. This specifically affects processors based on
the 'Nehalem' and 'Westemere' core designs. This issue has
been mitigated by disabling 'lazy FPU' by default on all x86
processors that support the FXSAVE and FXRSTOR instructions,
which includes all processors known to be affected and most
processors that perform speculative execution. It can also
be mitigated by adding the kernel parameter: eagerfpu=on

CVE-2018-5814

Jakub Jirasek reported race conditions in the USB/IP host driver. A
malicious client could use this to cause a denial of service (crash or
memory corruption), and possibly to execute code, on a USB/IP server.

CVE-2018-9422

It was reported that the futex() system call could be used by an
unprivileged user for privilege escalation.

CVE-2018-10853

Andy Lutomirski and Mika Penttil&auml; reported that KVM for x86
processors did not perform a necessary privilege check when emulating
certain instructions. This could be used by an unprivileged user in a
guest VM to escalate their privileges within the guest.

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
3.16.57-1. This update additionally fixes Debian bug #898165, and
includes many more bug fixes from stable update 3.16.57.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.57-2")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.57-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
