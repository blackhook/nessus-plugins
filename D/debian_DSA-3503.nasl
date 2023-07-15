#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3503. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89122);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-4312", "CVE-2015-7566", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2015-8830", "CVE-2016-0723", "CVE-2016-0774", "CVE-2016-2069", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2550", "CVE-2016-2847");
  script_xref(name:"DSA", value:"3503");

  script_name(english:"Debian DSA-3503-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service, information
leak or data loss.

  - CVE-2013-4312, CVE-2016-2847
    Tetsuo Handa discovered that users can use pipes queued
    on local (Unix) sockets to allocate an unfair share of
    kernel memory, leading to denial-of-service (resource
    exhaustion).

  This issue was previously mitigated for the stable suite by limiting
  the total number of files queued by each user on local sockets. The
  new kernel version in both suites includes that mitigation plus
  limits on the total size of pipe buffers allocated for each user.

  - CVE-2015-7566
    Ralf Spenneberg of OpenSource Security reported that the
    visor driver crashes when a specially crafted USB device
    without bulk-out endpoint is detected.

  - CVE-2015-8767
    An SCTP denial-of-service was discovered which can be
    triggered by a local attacker during a heartbeat timeout
    event after the 4-way handshake.

  - CVE-2015-8785
    It was discovered that local users permitted to write to
    a file on a FUSE filesystem could cause a denial of
    service (unkillable loop in the kernel).

  - CVE-2015-8812
    A flaw was found in the iw_cxgb3 Infiniband driver.
    Whenever it could not send a packet because the network
    was congested, it would free the packet buffer but later
    attempt to send the packet again. This use-after-free
    could result in a denial of service (crash or hang),
    data loss or privilege escalation.

  - CVE-2015-8816
    A use-after-free vulnerability was discovered in the USB
    hub driver. This may be used by a physically present
    user for privilege escalation.

  - CVE-2015-8830
    Ben Hawkes of Google Project Zero reported that the AIO
    interface permitted reading or writing 2 GiB of data or
    more in a single chunk, which could lead to an integer
    overflow when applied to certain filesystems, socket or
    device types. The full security impact has not been
    evaluated.

  - CVE-2016-0723
    A use-after-free vulnerability was discovered in the
    TIOCGETD ioctl. A local attacker could use this flaw for
    denial-of-service.

  - CVE-2016-0774
    It was found that the fix for CVE-2015-1805 in kernel
    versions older than Linux 3.16 did not correctly handle
    the case of a partially failed atomic read. A local,
    unprivileged user could use this flaw to crash the
    system or leak kernel memory to user space.

  - CVE-2016-2069
    Andy Lutomirski discovered a race condition in flushing
    of the TLB when switching tasks on an x86 system. On an
    SMP system this could possibly lead to a crash,
    information leak or privilege escalation.

  - CVE-2016-2384
    Andrey Konovalov found that a crafted USB MIDI device
    with an invalid USB descriptor could trigger a
    double-free. This may be used by a physically present
    user for privilege escalation.

  - CVE-2016-2543
    Dmitry Vyukov found that the core sound sequencer driver
    (snd-seq) lacked a necessary check for a NULL pointer,
    allowing a user with access to a sound sequencer device
    to cause a denial-of service (crash).

  - CVE-2016-2544, CVE-2016-2546, CVE-2016-2547,
    CVE-2016-2548

    Dmitry Vyukov found various race conditions in the sound
    subsystem (ALSA)'s management of timers. A user with
    access to sound devices could use these to cause a
    denial-of-service (crash or hang) or possibly for
    privilege escalation.

  - CVE-2016-2545
    Dmitry Vyukov found a flaw in list manipulation in the
    sound subsystem (ALSA)'s management of timers. A user
    with access to sound devices could use this to cause a
    denial-of-service (crash or hang) or possibly for
    privilege escalation.

  - CVE-2016-2549
    Dmitry Vyukov found a potential deadlock in the sound
    subsystem (ALSA)'s use of high resolution timers. A user
    with access to sound devices could use this to cause a
    denial-of-service (hang).

  - CVE-2016-2550
    The original mitigation of CVE-2013-4312, limiting the
    total number of files a user could queue on local
    sockets, was flawed. A user given a local socket opened
    by another user, for example through the systemd socket
    activation mechanism, could make use of the other user's
    quota, again leading to a denial-of-service (resource
    exhaustion). This is fixed by accounting queued files to
    the sender rather than the socket opener."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3503"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 3.2.73-2+deb7u3. The oldstable distribution (wheezy)
is not affected by CVE-2015-8830.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt20-1+deb8u4. CVE-2013-4312, CVE-2015-7566,
CVE-2015-8767 and CVE-2016-0723 were already fixed in DSA-3448-1.
CVE-2016-0774 does not affect the stable distribution."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.73-2+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.7-ckt20-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.7-ckt20-1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
