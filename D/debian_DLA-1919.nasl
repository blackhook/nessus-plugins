#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1919-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128779);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-0136", "CVE-2019-11487", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15807", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-9506");

  script_name(english:"Debian DLA-1919-2 : linux-4.9 security update");
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

This updated advisory text mentions the additional non-security
changes and notes the need to install new binary packages.

CVE-2019-0136

It was discovered that the wifi soft-MAC implementation (mac80211) did
not properly authenticate Tunneled Direct Link Setup (TDLS) messages.
A nearby attacker could use this for denial of service (loss of wifi
connectivity).

CVE-2019-9506

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen
discovered a weakness in the Bluetooth pairing protocols, dubbed the
'KNOB attack'. An attacker that is nearby during pairing could use
this to weaken the encryption used between the paired devices, and
then to eavesdrop on and/or spoof communication between them.

This update mitigates the attack by requiring a minimum
encryption key length of 56 bits.

CVE-2019-11487

Jann Horn discovered that the FUSE (Filesystem-in-Userspace) facility
could be used to cause integer overflow in page reference counts,
leading to a use-after-free. On a system with sufficient physical
memory, a local user permitted to create arbitrary FUSE mounts could
use this for privilege escalation.

By default, unprivileged users can only mount FUSE
filesystems through fusermount, which limits the number of
mounts created and should completely mitigate the issue.

CVE-2019-15211

The syzkaller tool found a bug in the radio-raremono driver that could
lead to a use-after-free. An attacker able to add and remove USB
devices could use this to cause a denial of service (memory corruption
or crash) or possibly for privilege escalation.

CVE-2019-15212

The syzkaller tool found that the rio500 driver does not work
correctly if more than one device is bound to it. An attacker able to
add USB devices could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

CVE-2019-15215

The syzkaller tool found a bug in the cpia2_usb driver that leads to a
use-after-free. An attacker able to add and remove USB devices could
use this to cause a denial of service (memory corruption or crash) or
possibly for privilege escalation.

CVE-2019-15216

The syzkaller tool found a bug in the yurex driver that leads to a
use-after-free. An attacker able to add and remove USB devices could
use this to cause a denial of service (memory corruption or crash) or
possibly for privilege escalation.

CVE-2019-15218

The syzkaller tool found that the smsusb driver did not validate that
USB devices have the expected endpoints, potentially leading to a NULL pointer dereference. An attacker able to add USB devices could use
this to cause a denial of service (BUG/oops).

CVE-2019-15219

The syzkaller tool found that a device initialisation error in the
sisusbvga driver could lead to a NULL pointer dereference. An attacker
able to add USB devices could use this to cause a denial of service
(BUG/oops).

CVE-2019-15220

The syzkaller tool found a race condition in the p54usb driver which
could lead to a use-after-free. An attacker able to add and remove USB
devices could use this to cause a denial of service (memory corruption
or crash) or possibly for privilege escalation.

CVE-2019-15221

The syzkaller tool found that the line6 driver did not validate USB
devices' maximum packet sizes, which could lead to a heap buffer
overrun. An attacker able to add USB devices could use this to cause a
denial of service (memory corruption or crash) or possibly for
privilege escalation.

CVE-2019-15292

The Hulk Robot tool found missing error checks in the Appletalk
protocol implementation, which could lead to a use-after-free. The
security impact of this is unclear.

CVE-2019-15538

Benjamin Moody reported that operations on XFS hung after a chgrp
command failed due to a disk quota. A local user on a system using XFS
and disk quotas could use this for denial of service.

CVE-2019-15666

The Hulk Robot tool found an incorrect range check in the network
transformation (xfrm) layer, leading to out-of-bounds memory accesses.
A local user with CAP_NET_ADMIN capability (in any user namespace)
could use this to cause a denial of service (memory corruption or
crash) or possibly for privilege escalation.

CVE-2019-15807

Jian Luo reported that the Serial Attached SCSI library (libsas) did
not correctly handle failure to discover devices beyond a SAS
expander. This could lead to a resource leak and crash (BUG). The
security impact of this is unclear.

CVE-2019-15924

The Hulk Robot tool found a missing error check in the fm10k Ethernet
driver, which could lead to a NULL pointer dereference and crash
(BUG/oops). The security impact of this is unclear.

CVE-2019-15926

It was found that the ath6kl wifi driver did not consistently validate
traffic class numbers in received control packets, leading to
out-of-bounds memory accesses. A nearby attacker on the same wifi
network could use this to cause a denial of service (memory corruption
or crash) or possibly for privilege escalation.

For Debian 8 'Jessie', these problems have been fixed in version
4.9.189-3. This version also includes a fix for Debian bug #930904,
and other fixes included in upstream stable updates.

We recommend that you upgrade your linux-4.9 and linux-latest-4.9
packages. You will need to use 'apt-get upgrade --with-new-pkgs' or
'apt upgrade' as the binary package names have changed.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux-4.9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-arm", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-4.9", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686-pae", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-amd64", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armel", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armhf", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-i386", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-amd64", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common-rt", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-marvell", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64-dbg", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-marvell", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-kbuild-4.9", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-4.9", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-perf-4.9", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-4.9", reference:"4.9.189-3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-4.9.0-0.bpo.7", reference:"4.9.189-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
