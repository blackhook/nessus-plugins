#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1531-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117908);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-10902", "CVE-2018-10938", "CVE-2018-13099", "CVE-2018-14609", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-14678", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-15594", "CVE-2018-16276", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-7755", "CVE-2018-9363", "CVE-2018-9516");

  script_name(english:"Debian DLA-1531-1 : linux-4.9 security update");
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

CVE-2018-6554

A memory leak in the irda_bind function in the irda subsystem was
discovered. A local user can take advantage of this flaw to cause a
denial of service (memory consumption).

CVE-2018-6555

A flaw was discovered in the irda_setsockopt function in the irda
subsystem, allowing a local user to cause a denial of service
(use-after-free and system crash).

CVE-2018-7755

Brian Belleville discovered a flaw in the fd_locked_ioctl function in
the floppy driver in the Linux kernel. The floppy driver copies a
kernel pointer to user memory in response to the FDGETPRM ioctl. A
local user with access to a floppy drive device can take advantage of
this flaw to discover the location kernel code and data.

CVE-2018-9363

It was discovered that the Bluetooth HIDP implementation did not
correctly check the length of received report messages. A paired HIDP
device could use this to cause a buffer overflow, leading to denial of
service (memory corruption or crash) or potentially remote code
execution.

CVE-2018-9516

It was discovered that the HID events interface in debugfs did not
correctly limit the length of copies to user buffers. A local user
with access to these files could use this to cause a denial of service
(memory corruption or crash) or possibly for privilege escalation.
However, by default debugfs is only accessible by the root user.

CVE-2018-10902

It was discovered that the rawmidi kernel driver does not protect
against concurrent access which leads to a double-realloc (double
free) flaw. A local attacker can take advantage of this issue for
privilege escalation.

CVE-2018-10938

Yves Younan from Cisco reported that the Cipso IPv4 module did not
correctly check the length of IPv4 options. On custom kernels with
CONFIG_NETLABEL enabled, a remote attacker could use this to cause a
denial of service (hang).

CVE-2018-13099

Wen Xu from SSLab at Gatech reported a use-after-free bug in the F2FS
implementation. An attacker able to mount a crafted F2FS volume could
use this to cause a denial of service (crash or memory corruption) or
possibly for privilege escalation.

CVE-2018-14609

Wen Xu from SSLab at Gatech reported a potential NULL pointer
dereference in the F2FS implementation. An attacker able to mount
arbitrary F2FS volumes could use this to cause a denial of service
(crash).

CVE-2018-14617

Wen Xu from SSLab at Gatech reported a potential NULL pointer
dereference in the HFS+ implementation. An attacker able to mount
arbitrary HFS+ volumes could use this to cause a denial of service
(crash).

CVE-2018-14633

Vincent Pelletier discovered a stack-based buffer overflow flaw in the
chap_server_compute_md5() function in the iSCSI target code. An
unauthenticated remote attacker can take advantage of this flaw to
cause a denial of service or possibly to get a non-authorized access
to data exported by an iSCSI target.

CVE-2018-14678

M. Vefa Bicakci and Andy Lutomirski discovered a flaw in the kernel
exit code used on amd64 systems running as Xen PV guests. A local user
could use this to cause a denial of service (crash).

CVE-2018-14734

A use-after-free bug was discovered in the InfiniBand communication
manager. A local user could use this to cause a denial of service
(crash or memory corruption) or possible for privilege escalation.

CVE-2018-15572

Esmaiel Mohammadian Koruyeh, Khaled Khasawneh, Chengyu Song, and Nael
Abu-Ghazaleh, from University of California, Riverside, reported a
variant of Spectre variant 2, dubbed SpectreRSB. A local user may be
able to use this to read sensitive information from processes owned by
other users.

CVE-2018-15594

Nadav Amit reported that some indirect function calls used in
paravirtualised guests were vulnerable to Spectre variant 2. A local
user may be able to use this to read sensitive information from the
kernel.

CVE-2018-16276

Jann Horn discovered that the yurex driver did not correctly limit the
length of copies to user buffers. A local user with access to a yurex
device node could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

CVE-2018-16658

It was discovered that the cdrom driver does not correctly validate
the parameter to the CDROM_DRIVE_STATUS ioctl. A user with access to a
cdrom device could use this to read sensitive information from the
kernel or to cause a denial of service (crash).

CVE-2018-17182

Jann Horn discovered that the vmacache_flush_all function mishandles
sequence number overflows. A local user can take advantage of this
flaw to trigger a use-after-free, causing a denial of service (crash
or memory corruption) or privilege escalation.

For Debian 8 'Jessie', these problems have been fixed in version
4.9.110-3+deb9u5~deb8u1.

We recommend that you upgrade your linux-4.9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux-4.9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/04");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-arm", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-4.9", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686-pae", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-amd64", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armel", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armhf", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-i386", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-amd64", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common-rt", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-marvell", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64-dbg", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-marvell", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-kbuild-4.9", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-4.9", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-perf-4.9", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-4.9", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-4.9.0-0.bpo.7", reference:"4.9.110-3+deb9u5~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
