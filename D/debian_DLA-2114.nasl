#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2114-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134240);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2018-13093", "CVE-2018-13094", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-0136", "CVE-2019-10220", "CVE-2019-14615", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-15098", "CVE-2019-15217", "CVE-2019-15291", "CVE-2019-15505", "CVE-2019-15917", "CVE-2019-16746", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-18282", "CVE-2019-18683", "CVE-2019-18809", "CVE-2019-19037", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19447", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19767", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-20096", "CVE-2019-2215");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Debian DLA-2114-1 : linux-4.9 security update");
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

CVE-2018-13093, CVE-2018-13094

Wen Xu from SSLab at Gatech reported several NULL pointer dereference
flaws that may be triggered when mounting and operating a crafted XFS
volume. An attacker able to mount arbitrary XFS volumes could use this
to cause a denial of service (crash).

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

CVE-2019-14615

It was discovered that Intel 9th and 10th generation GPUs did not
clear user-visible state during a context switch, which resulted in
information leaks between GPU tasks. This has been mitigated in the
i915 driver.

The affected chips (gen9 and gen10) are listed at
<https://en.wikipedia.org/wiki/List_of_Intel_graphics_proces
sing_units#Gen9>.

CVE-2019-14814, CVE-2019-14815, CVE-2019-14816

Multiple bugs were discovered in the mwifiex wifi driver, which could
lead to heap buffer overflows. A local user permitted to configure a
device handled by this driver could probably use this for privilege
escalation.

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

CVE-2019-15917

The syzkaller tool found a race condition in code supporting
UART-attached Bluetooth adapters, which could lead to a use-
after-free. A local user with access to a pty device or other suitable
tty device could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

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

CVE-2019-17075

It was found that the cxgb4 Infiniband driver requested DMA (Direct
Memory Access) to a stack-allocated buffer, which is not supported and
on some systems can result in memory corruption of the stack. A local
user might be able to use this for denial of service (memory
corruption or crash) or possibly for privilege escalation.

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

CVE-2019-18282

Jonathan Berger, Amit Klein, and Benny Pinkas discovered that the
generation of UDP/IPv6 flow labels used a weak hash function, 'jhash'.
This could enable tracking individual computers as they communicate
with different remote servers and from different networks. The
'siphash' function is now used instead.

CVE-2019-18683

Multiple race conditions were discovered in the vivid media driver,
used for testing Video4Linux2 (V4L2) applications, These race
conditions could result in a use-after-free. On a system where this
driver is loaded, a user with permission to access media devices could
use this to cause a denial of service (memory corruption or crash) or
possibly for privilege escalation.

CVE-2019-18809

Navid Emamdoost discovered a potential memory leak in the af9005 media
driver if the device fails to respond to a command. The security
impact of this is unclear.

CVE-2019-19037

It was discovered that the ext4 filesystem driver did not correctly
handle directories with holes (unallocated regions) in them. An
attacker able to mount arbitrary ext4 volumes could use this to cause
a denial of service (crash).

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

CVE-2019-19068

Navid Emamdoost discovered a potential memory leak in the rtl8xxxu
wifi driver, in case it fails to submit an interrupt buffer to the
device. The security impact of this is unclear.

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

CVE-2019-19447

It was discovered that the ext4 filesystem driver did not safely
handle unlinking of an inode that, due to filesystem corruption,
already has a link count of 0. An attacker able to mount arbitrary
ext4 volumes could use this to cause a denial of service (memory
corruption or crash) or possibly for privilege escalation.

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

CVE-2019-19525

The syzkaller tool discovered a use-after-free bug in the atusb driver
for IEEE 802.15.4 networking. An attacker able to add and remove USB
devices could possibly use this to cause a denial of service (memory
corruption or crash) or for privilege escalation.

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

CVE-2019-19534, CVE-2019-19535, CVE-2019-19536

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

CVE-2019-19947

It was discovered that the kvaser_usb CAN driver was missing
initialisation of some structures, which could leak sensitive
information from kernel memory.

CVE-2019-19965

Gao Chuan reported a race condition in the libsas library used by SCSI
host drivers, which could lead to a NULL pointer dereference. An
attacker able to add and remove SCSI devices could use this to cause a
denial of service (BUG/oops).

CVE-2019-20096

The Hulk Robot tool discovered a potential memory leak in the DCCP
protocol implementation. This may be exploitable by local users, or by
remote attackers if the system uses DCCP, to cause a denial of service
(out of memory).

For Debian 8 'Jessie', these problems have been fixed in version
4.9.210-1~deb8u1. This update additionally fixes Debian bugs #869511
and 945023; and includes many more bug fixes from stable updates
4.9.190-4.9.210 inclusive.

We recommend that you upgrade your linux-4.9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://en.wikipedia.org/wiki/List_of_Intel_graphics_processing_units#Gen9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09b1ea0a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00001.html"
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
  script_set_attribute(attribute:"metasploit_name", value:'Android Binder Use-After-Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-arm", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-4.9", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686-pae", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-amd64", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armel", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armhf", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-i386", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-amd64", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common-rt", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-marvell", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64-dbg", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-marvell", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-kbuild-4.9", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-4.9", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-perf-4.9", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-4.9", reference:"4.9.210-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-4.9.0-0.bpo.7", reference:"4.9.210-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
