#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1930-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129361);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-10905", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-0136", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15292", "CVE-2019-15807", "CVE-2019-15917", "CVE-2019-15926", "CVE-2019-9506");

  script_name(english:"Debian DLA-1930-1 : linux security update");
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

CVE-2016-10905

A race condition was discovered in the GFS2 file-system
implementation, which could lead to a use-after-free. On a system
using GFS2, a local attacker could use this for denial of service
(memory corruption or crash) or possibly for privilege escalation.

CVE-2018-20976

It was discovered that the XFS file-system implementation did not
correctly handle some mount failure conditions, which could lead to a
use-after-free. The security impact of this is unclear.

CVE-2018-21008

It was discovered that the rsi wifi driver did not correctly handle
some failure conditions, which could lead to a use-after- free. The
security impact of this is unclear.

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

CVE-2019-14814, CVE-2019-14815, CVE-2019-14816

Multiple bugs were discovered in the mwifiex wifi driver, which could
lead to heap buffer overflows. A local user permitted to configure a
device handled by this driver could probably use this for privilege
escalation.

CVE-2019-14821

Matt Delco reported a race condition in KVM's coalesced MMIO facility,
which could lead to out-of-bounds access in the kernel. A local
attacker permitted to access /dev/kvm could use this to cause a denial
of service (memory corruption or crash) or possibly for privilege
escalation.

CVE-2019-14835

Peter Pi of Tencent Blade Team discovered a missing bounds check in
vhost_net, the network back-end driver for KVM hosts, leading to a
buffer overflow when the host begins live migration of a VM. An
attacker in control of a VM could use this to cause a denial of
service (memory corruption or crash) or possibly for privilege
escalation on the host.

CVE-2019-15117

Hui Peng and Mathias Payer reported a missing bounds check in the
usb-audio driver's descriptor parsing code, leading to a buffer
over-read. An attacker able to add USB devices could possibly use this
to cause a denial of service (crash).

CVE-2019-15118

Hui Peng and Mathias Payer reported unbounded recursion in the
usb-audio driver's descriptor parsing code, leading to a stack
overflow. An attacker able to add USB devices could use this to cause
a denial of service (memory corruption or crash) or possibly for
privilege escalation.

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

CVE-2019-15807

Jian Luo reported that the Serial Attached SCSI library (libsas) did
not correctly handle failure to discover devices beyond a SAS
expander. This could lead to a resource leak and crash (BUG). The
security impact of this is unclear.

CVE-2019-15917

The syzkaller tool found a race condition in code supporting
UART-attached Bluetooth adapters, which could lead to a use-
after-free. A local user with access to a pty device or other suitable
tty device could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

CVE-2019-15926

It was found that the ath6kl wifi driver did not consistently validate
traffic class numbers in received control packets, leading to
out-of-bounds memory accesses. A nearby attacker on the same wifi
network could use this to cause a denial of service (memory corruption
or crash) or possibly for privilege escalation.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.74-1.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.74-1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.74-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
