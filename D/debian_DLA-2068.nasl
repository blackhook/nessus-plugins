#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2068-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133101);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2019-10220", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-15098", "CVE-2019-15217", "CVE-2019-15291", "CVE-2019-15505", "CVE-2019-16746", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19066", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19767", "CVE-2019-19922", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-2215");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Debian DLA-2068-1 : linux security update");
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

CVE-2019-2215

The syzkaller tool discovered a use-after-free vulnerability in the
Android binder driver. A local user on a system with this driver
enabled could use this to cause a denial of service (memory corruption
or crash) or possibly for privilege escalation. However, this driver
is not enabled on Debian packaged kernels.

CVE-2019-10220

Various developers and researchers found that if a crafted file-
system or malicious file server presented a directory with filenames
including a '/' character, this could confuse and possibly defeat
security checks in applications that read the directory.

The kernel will now return an error when reading such a
directory, rather than passing the invalid filenames on to
user-space.

CVE-2019-14895, CVE-2019-14901

ADLab of Venustech discovered potential heap buffer overflows in the
mwifiex wifi driver. On systems using this driver, a malicious
Wireless Access Point or adhoc/P2P peer could use these to cause a
denial of service (memory corruption or crash) or possibly for remote
code execution.

CVE-2019-14896, CVE-2019-14897

ADLab of Venustech discovered potential heap and stack buffer
overflows in the libertas wifi driver. On systems using this driver, a
malicious Wireless Access Point or adhoc/P2P peer could use these to
cause a denial of service (memory corruption or crash) or possibly for
remote code execution.

CVE-2019-15098

Hui Peng and Mathias Payer reported that the ath6kl wifi driver did
not properly validate USB descriptors, which could lead to a NULL pointer derefernce. An attacker able to add USB devices could use this
to cause a denial of service (BUG/oops).

CVE-2019-15217

The syzkaller tool discovered that the zr364xx mdia driver did not
correctly handle devices without a product name string, which could
lead to a NULL pointer dereference. An attacker able to add USB
devices could use this to cause a denial of service (BUG/oops).

CVE-2019-15291

The syzkaller tool discovered that the b2c2-flexcop-usb media driver
did not properly validate USB descriptors, which could lead to a NULL pointer dereference. An attacker able to add USB devices could use
this to cause a denial of service (BUG/oops).

CVE-2019-15505

The syzkaller tool discovered that the technisat-usb2 media driver did
not properly validate incoming IR packets, which could lead to a heap
buffer over-read. An attacker able to add USB devices could use this
to cause a denial of service (BUG/oops) or to read sensitive
information from kernel memory.

CVE-2019-16746

It was discovered that the wifi stack did not validate the content of
beacon heads provided by user-space for use on a wifi interface in
Access Point mode, which could lead to a heap buffer overflow. A local
user permitted to configure a wifi interface could use this to cause a
denial of service (memory corruption or crash) or possibly for
privilege escalation.

CVE-2019-17052, CVE-2019-17053, CVE-2019-17054, CVE-2019-17055,
CVE-2019-17056

Ori Nimron reported that various network protocol implementations

  - AX.25, IEEE 802.15.4, Appletalk, ISDN, and NFC - allowed
    all users to create raw sockets. A local user could use
    this to send arbitrary packets on networks using those
    protocols.

CVE-2019-17133

Nicholas Waisman reported that the wifi stack did not valdiate
received SSID information before copying it, which could lead to a
buffer overflow if it is not validated by the driver or firmware. A
malicious Wireless Access Point might be able to use this to cause a
denial of service (memory corruption or crash) or for remote code
execution.

CVE-2019-17666

Nicholas Waisman reported that the rtlwifi wifi drivers did not
properly validate received P2P information, leading to a buffer
overflow. A malicious P2P peer could use this to cause a denial of
service (memory corruption or crash) or for remote code execution.

CVE-2019-19051

Navid Emamdoost discovered a potential memory leak in the i2400m wimax
driver if the software rfkill operation fails. The security impact of
this is unclear.

CVE-2019-19052

Navid Emamdoost discovered a potential memory leak in the gs_usb CAN
driver if the open (interface-up) operation fails. The security impact
of this is unclear.

CVE-2019-19056, CVE-2019-19057

Navid Emamdoost discovered potential memory leaks in the mwifiex wifi
driver if the probe operation fails. The security impact of this is
unclear.

CVE-2019-19062

Navid Emamdoost discovered a potential memory leak in the AF_ALG
subsystem if the CRYPTO_MSG_GETALG operation fails. A local user could
possibly use this to cause a denial of service (memory exhaustion).

CVE-2019-19066

Navid Emamdoost discovered a potential memory leak in the bfa SCSI
driver if the get_fc_host_stats operation fails. The security impact
of this is unclear.

CVE-2019-19227

Dan Carpenter reported missing error checks in the Appletalk protocol
implementation that could lead to a NULL pointer dereference. The
security impact of this is unclear.

CVE-2019-19332

The syzkaller tool discovered a missing bounds check in the KVM
implementation for x86, which could lead to a heap buffer overflow. A
local user permitted to use KVM could use this to cause a denial of
service (memory corruption or crash) or possibly for privilege
escalation.

CVE-2019-19523

The syzkaller tool discovered a use-after-free bug in the adutux USB
driver. An attacker able to add and remove USB devices could use this
to cause a denial of service (memory corruption or crash) or possibly
for privilege escalation.

CVE-2019-19524

The syzkaller tool discovered a race condition in the ff-memless
library used by input drivers. An attacker able to add and remove USB
devices could use this to cause a denial of service (memory corruption
or crash) or possibly for privilege escalation.

CVE-2019-19527

The syzkaller tool discovered that the hiddev driver did not correctly
handle races between a task opening the device and disconnection of
the underlying hardware. A local user permitted to access hiddev
devices, and able to add and remove USB devices, could use this to
cause a denial of service (memory corruption or crash) or possibly for
privilege escalation.

CVE-2019-19530

The syzkaller tool discovered a potential use-after-free in the
cdc-acm network driver. An attacker able to add USB devices could use
this to cause a denial of service (memory corruption or crash) or
possibly for privilege escalation.

CVE-2019-19531

The syzkaller tool discovered a use-after-free bug in the yurex USB
driver. An attacker able to add and remove USB devices could use this
to cause a denial of service (memory corruption or crash) or possibly
for privilege escalation.

CVE-2019-19532

The syzkaller tool discovered a potential heap buffer overflow in the
hid-gaff input driver, which was also found to exist in many other
input drivers. An attacker able to add USB devices could use this to
cause a denial of service (memory corruption or crash) or possibly for
privilege escalation.

CVE-2019-19533

The syzkaller tool discovered that the ttusb-dec media driver was
missing initialisation of a structure, which could leak sensitive
information from kernel memory.

CVE-2019-19534, CVE-2019-19536

The syzkaller tool discovered that the peak_usb CAN driver was missing
initialisation of some structures, which could leak sensitive
information from kernel memory.

CVE-2019-19537

The syzkaller tool discovered race conditions in the USB stack,
involving character device registration. An attacker able to add USB
devices could use this to cause a denial of service (memory corruption
or crash) or possibly for privilege escalation.

CVE-2019-19767

The syzkaller tool discovered that crafted ext4 volumes could trigger
a buffer overflow in the ext4 filesystem driver. An attacker able to
mount such a volume could use this to cause a denial of service
(memory corruption or crash) or possibly for privilege escalation.

CVE-2019-19922

It was discovered that a change in Linux 3.16.61, 'sched/fair: Fix
bandwidth timer clock drift condition', could lead to tasks being
throttled before using their full quota of CPU time. A local user
could use this bug to slow down other users' tasks. This change has
been reverted.

CVE-2019-19947

It was discovered that the kvaser_usb CAN driver was missing
initialisation of some structures, which could leak sensitive
information from kernel memory.

CVE-2019-19965

Gao Chuan reported a race condition in the libsas library used by SCSI
host drivers, which could lead to a NULL pointer dereference. An
attacker able to add and remove SCSI devices could use this to cause a
denial of service (BUG/oops).

CVE-2019-19966

The syzkaller tool discovered a missing error check in the cpia2 media
driver, which could lead to a use-after-free. An attacker able to add
USB devices could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.81-1.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Binder Use-After-Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.81-1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.81-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
