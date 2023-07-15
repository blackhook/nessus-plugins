#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3981. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103365);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-1000251", "CVE-2017-1000252", "CVE-2017-1000370", "CVE-2017-1000371", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-12146", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-14497", "CVE-2017-7518", "CVE-2017-7558");
  script_xref(name:"DSA", value:"3981");

  script_name(english:"Debian DSA-3981-1 : linux - security update (BlueBorne) (Stack Clash)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to privilege escalation, denial of service or information
leaks.

  - CVE-2017-7518
    Andy Lutomirski discovered that KVM is prone to an
    incorrect debug exception (#DB) error occurring while
    emulating a syscall instruction. A process inside a
    guest can take advantage of this flaw for privilege
    escalation inside a guest.

  - CVE-2017-7558 (stretch only)
    Stefano Brivio of Red Hat discovered that the SCTP
    subsystem is prone to a data leak vulnerability due to
    an out-of-bounds read flaw, allowing to leak up to 100
    uninitialized bytes to userspace.

  - CVE-2017-10661 (jessie only)
    Dmitry Vyukov of Google reported that the timerfd
    facility does not properly handle certain concurrent
    operations on a single file descriptor. This allows a
    local attacker to cause a denial of service or
    potentially execute arbitrary code.

  - CVE-2017-11600
    Bo Zhang reported that the xfrm subsystem does not
    properly validate one of the parameters to a netlink
    message. Local users with the CAP_NET_ADMIN capability
    can use this to cause a denial of service or potentially
    to execute arbitrary code.

  - CVE-2017-12134 / #866511 / XSA-229
    Jan H. Schoenherr of Amazon discovered that when Linux
    is running in a Xen PV domain on an x86 system, it may
    incorrectly merge block I/O requests. A buggy or
    malicious guest may trigger this bug in dom0 or a PV
    driver domain, causing a denial of service or
    potentially execution of arbitrary code.

  This issue can be mitigated by disabling merges on the underlying
  back-end block devices, e.g.:echo 2 >
  /sys/block/nvme0n1/queue/nomerges

  - CVE-2017-12146 (stretch only)
    Adrian Salido of Google reported a race condition in
    access to the'driver_override' attribute for platform
    devices in sysfs. If unprivileged users are permitted to
    access this attribute, this might allow them to gain
    privileges.

  - CVE-2017-12153
    Bo Zhang reported that the cfg80211 (wifi) subsystem
    does not properly validate the parameters to a netlink
    message. Local users with the CAP_NET_ADMIN capability
    (in any user namespace with a wifi device) can use this
    to cause a denial of service.

  - CVE-2017-12154
    Jim Mattson of Google reported that the KVM
    implementation for Intel x86 processors did not
    correctly handle certain nested hypervisor
    configurations. A malicious guest (or nested guest in a
    suitable L1 hypervisor) could use this for denial of
    service.

  - CVE-2017-14106
    Andrey Konovalov discovered that a user-triggerable
    division by zero in the tcp_disconnect() function could
    result in local denial of service.

  - CVE-2017-14140
    Otto Ebeling reported that the move_pages() system call
    performed insufficient validation of the UIDs of the
    calling and target processes, resulting in a partial
    ASLR bypass. This made it easier for local users to
    exploit vulnerabilities in programs installed with the
    set-UID permission bit set.

  - CVE-2017-14156
    'sohu0106' reported an information leak in the atyfb
    video driver. A local user with access to a framebuffer
    device handled by this driver could use this to obtain
    sensitive information.

  - CVE-2017-14340
    Richard Wareing discovered that the XFS implementation
    allows the creation of files with the 'realtime' flag on
    a filesystem with no realtime device, which can result
    in a crash (oops). A local user with access to an XFS
    filesystem that does not have a realtime device can use
    this for denial of service.

  - CVE-2017-14489
    ChunYu Wang of Red Hat discovered that the iSCSI
    subsystem does not properly validate the length of a
    netlink message, leading to memory corruption. A local
    user with permission to manage iSCSI devices can use
    this for denial of service or possibly to execute
    arbitrary code.

  - CVE-2017-14497 (stretch only)
    Benjamin Poirier of SUSE reported that vnet headers are
    not properly handled within the tpacket_rcv() function
    in the raw packet (af_packet) feature. A local user with
    the CAP_NET_RAW capability can take advantage of this
    flaw to cause a denial of service (buffer overflow, and
    disk and memory corruption) or have other impact.

  - CVE-2017-1000111
    Andrey Konovalov of Google reported a race condition in
    the raw packet (af_packet) feature. Local users with the
    CAP_NET_RAW capability can use this for denial of
    service or possibly to execute arbitrary code.

  - CVE-2017-1000112
    Andrey Konovalov of Google reported a race condition
    flaw in the UDP Fragmentation Offload (UFO) code. A
    local user can use this flaw for denial of service or
    possibly to execute arbitrary code.

  - CVE-2017-1000251 / #875881
    Armis Labs discovered that the Bluetooth subsystem does
    not properly validate L2CAP configuration responses,
    leading to a stack-based buffer overflow. This is one of
    several vulnerabilities dubbed 'Blueborne'. A nearby
    attacker can use this to cause a denial of service or
    possibly to execute arbitrary code on a system with
    Bluetooth enabled.

  - CVE-2017-1000252 (stretch only)
    Jan H. Schoenherr of Amazon reported that the KVM
    implementation for Intel x86 processors did not
    correctly validate interrupt injection requests. A local
    user with permission to use KVM could use this for
    denial of service.

  - CVE-2017-1000370
    The Qualys Research Labs reported that a large argument
    or environment list can result in ASLR bypass for 32-bit
    PIE binaries.

  - CVE-2017-1000371
    The Qualys Research Labs reported that a large argument
    or environment list can result in a stack/heap clash for
    32-bit PIE binaries.

  - CVE-2017-1000380
    Alexander Potapenko of Google reported a race condition
    in the ALSA (sound) timer driver, leading to an
    information leak. A local user with permission to access
    sound devices could use this to obtain sensitive
    information.

Debian disables unprivileged user namespaces by default, but if they
are enabled (via the kernel.unprivileged_userns_clone sysctl) then
CVE-2017-11600, CVE-2017-14497 and CVE-2017-1000111 can be exploited
by any local user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=866511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-10661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-11600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-11600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-1000111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3981"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the linux packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 3.16.43-2+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 4.9.30-2+deb9u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/17");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.43-2+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"hyperv-daemons", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower-dev", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libcpupower1", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libusbip-dev", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-arm", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-s390", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-compiler-gcc-6-x86", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-cpupower", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.9", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-4kc-malta", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-5kc-malta", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-686-pae", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-amd64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-arm64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armel", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-armhf", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-i386", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mips64el", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-mipsel", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-ppc64el", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-all-s390x", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-amd64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-arm64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-armmp-lpae", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-common-rt", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-loongson-3", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-marvell", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-octeon", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-powerpc64le", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-686-pae", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-rt-amd64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.9.0-9-s390x", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-4kc-malta-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-5kc-malta-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-686-pae-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-amd64-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-arm64-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-armmp-lpae-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-loongson-3-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-marvell-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-octeon-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-powerpc64le-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-686-pae-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-rt-amd64-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.9.0-9-s390x-dbg", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.9", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-libc-dev", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-manual-4.9", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.9", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.9", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.9.0-9", reference:"4.9.30-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"usbip", reference:"4.9.30-2+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
