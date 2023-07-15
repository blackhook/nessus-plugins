#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1099-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103363);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000111", "CVE-2017-1000251", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-7482", "CVE-2017-7542", "CVE-2017-7889");

  script_name(english:"Debian DLA-1099-1 : linux security update (BlueBorne) (Stack Clash)");
  script_summary(english:"Checks dpkg output for the updated package.");

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

CVE-2017-7482

Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does not
properly verify metadata, leading to information disclosure, denial of
service or potentially execution of arbitrary code.

CVE-2017-7542

An integer overflow vulnerability in the ip6_find_1stfragopt()
function was found allowing a local attacker with privileges to open
raw sockets to cause a denial of service.

CVE-2017-7889

Tommi Rantala and Brad Spengler reported that the mm subsystem does
not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism,
allowing a local attacker with access to /dev/mem to obtain sensitive
information or potentially execute arbitrary code.

CVE-2017-10661

Dmitry Vyukov of Google reported that the timerfd facility does not
properly handle certain concurrent operations on a single file
descriptor. This allows a local attacker to cause a denial of service
or potentially to execute arbitrary code.

CVE-2017-10911 / XSA-216

Anthony Perard of Citrix discovered an information leak flaw in Xen
blkif response handling, allowing a malicious unprivileged guest to
obtain sensitive information from the host or other guests.

CVE-2017-11176

It was discovered that the mq_notify() function does not set the sock
pointer to NULL upon entry into the retry logic. An attacker can take
advantage of this flaw during a userspace close of a Netlink socket to
cause a denial of service or potentially cause other impact.

CVE-2017-11600

bo Zhang reported that the xfrm subsystem does not properly validate
one of the parameters to a netlink message. Local users with the
CAP_NET_ADMIN capability can use this to cause a denial of service or
potentially to execute arbitrary code.

CVE-2017-12134 / #866511 / XSA-229

Jan H. Sch&ouml;nherr of Amazon discovered that when Linux is running
in a Xen PV domain on an x86 system, it may incorrectly merge block
I/O requests. A buggy or malicious guest may trigger this bug in dom0
or a PV driver domain, causing a denial of service or potentially
execution of arbitrary code.

This issue can be mitigated by disabling merges on the
underlying back-end block devices, e.g.: echo 2 >
/sys/block/nvme0n1/queue/nomerges

CVE-2017-12153

bo Zhang reported that the cfg80211 (wifi) subsystem does not properly
validate the parameters to a netlink message. Local users with the
CAP_NET_ADMIN capability on a system with a wifi device can use this
to cause a denial of service.

CVE-2017-12154

Jim Mattson of Google reported that the KVM implementation for Intel
x86 processors did not correctly handle certain nested hypervisor
configurations. A malicious guest (or nested guest in a suitable L1
hypervisor) could use this for denial of service.

CVE-2017-14106

Andrey Konovalov of Google reported that a specific sequence of
operations on a TCP socket could lead to division by zero. A local
user could use this for denial of service.

CVE-2017-14140

Otto Ebeling reported that the move_pages() system call permitted
users to discover the memory layout of a set-UID process running under
their real user-ID. This made it easier for local users to exploit
vulnerabilities in programs installed with the set-UID permission bit
set.

CVE-2017-14156

'sohu0106' reported an information leak in the atyfb video driver. A
local user with access to a framebuffer device handled by this driver
could use this to obtain sensitive information.

CVE-2017-14340

Richard Wareing discovered that the XFS implementation allows the
creation of files with the 'realtime' flag on a filesystem with no
realtime device, which can result in a crash (oops). A local user with
access to an XFS filesystem that does not have a realtime device can
use this for denial of service.

CVE-2017-14489

ChunYu of Red Hat discovered that the iSCSI subsystem does not
properly validate the length of a netlink message, leading to memory
corruption. A local user with permission to manage iSCSI devices can
use this for denial of service or possibly to execute arbitrary code.

CVE-2017-1000111

Andrey Konovalov of Google reported that a race condition in the raw
packet (af_packet) feature. Local users with the CAP_NET_RAW
capability can use this to cause a denial of service or possibly to
execute arbitrary code.

CVE-2017-1000251 / #875881

Armis Labs discovered that the Bluetooth subsystem does not properly
validate L2CAP configuration responses, leading to a stack buffer
overflow. This is one of several vulnerabilities dubbed 'Blueborne'. A
nearby attacker can use this to cause a denial of service or possibly
to execute arbitrary code on a system with Bluetooth enabled.

CVE-2017-1000363

Roee Hay reported that the lp driver does not properly bounds-check
passed arguments. This has no security impact in Debian.

CVE-2017-1000365

It was discovered that argument and environment pointers are not
properly taken into account by the size restrictions on arguments and
environmental strings passed through execve(). A local attacker can
take advantage of this flaw in conjunction with other flaws to execute
arbitrary code.

CVE-2017-1000380

Alexander Potapenko of Google reported a race condition in the ALSA
(sound) timer driver, leading to an information leak. A local user
with permission to access sound devices could use this to obtain
sensitive information.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.93-1. This version also includes bug fixes from upstream versions
up to and including 3.2.93.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.43-2+deb8u4 or were fixed in an earlier version.

For Debian 9 'Stretch', these problems have been fixed in version
4.9.30-2+deb9u4 or were fixed in an earlier version.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00017.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.93-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
