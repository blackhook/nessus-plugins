#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3237. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83065);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-8159", "CVE-2014-9715", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3332", "CVE-2015-3339");
  script_bugtraq_id(72729, 72730, 73014, 73060, 73699, 73953, 74232, 74235, 74243, 74315);
  script_xref(name:"DSA", value:"3237");

  script_name(english:"Debian DSA-3237-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

  - CVE-2014-8159
    It was found that the Linux kernel's InfiniBand/RDMA
    subsystem did not properly sanitize input parameters
    while registering memory regions from user space via the
    (u)verbs API. A local user with access to a
    /dev/infiniband/uverbsX device could use this flaw to
    crash the system or, potentially, escalate their
    privileges on the system.

  - CVE-2014-9715
    It was found that the netfilter connection tracking
    subsystem used too small a type as an offset within each
    connection's data structure, following a bug fix in
    Linux 3.2.33 and 3.6. In some configurations, this would
    lead to memory corruption and crashes (even without
    malicious traffic). This could potentially also result
    in violation of the netfilter policy or remote code
    execution.

  This can be mitigated by disabling connection tracking
  accounting:sysctl net.netfilter.nf_conntrack_acct=0

  - CVE-2015-2041
    Sasha Levin discovered that the LLC subsystem exposed
    some variables as sysctls with the wrong type. On a
    64-bit kernel, this possibly allows privilege escalation
    from a process with CAP_NET_ADMIN capability; it also
    results in a trivial information leak.

  - CVE-2015-2042
    Sasha Levin discovered that the RDS subsystem exposed
    some variables as sysctls with the wrong type. On a
    64-bit kernel, this results in a trivial information
    leak.

  - CVE-2015-2150
    Jan Beulich discovered that Xen guests are currently
    permitted to modify all of the (writable) bits in the
    PCI command register of devices passed through to them.
    This in particular allows them to disable memory and I/O
    decoding on the device unless the device is an SR-IOV
    virtual function, which can result in denial of service
    to the host.

  - CVE-2015-2830
    Andrew Lutomirski discovered that when a 64-bit task on
    an amd64 kernel makes a fork(2) or clone(2) system call
    using int $0x80, the 32-bit compatibility flag is set
    (correctly) but is not cleared on return. As a result,
    both seccomp and audit will misinterpret the following
    system call by the task(s), possibly leading to a
    violation of security policy.

  - CVE-2015-2922
    Modio AB discovered that the IPv6 subsystem would
    process a router advertisement that specifies no route
    but only a hop limit, which would then be applied to the
    interface that received it. This can result in loss of
    IPv6 connectivity beyond the local network.

  This may be mitigated by disabling processing of IPv6 router
  advertisements if they are not needed:sysctl
  net.ipv6.conf.default.accept_ra=0sysctl
  net.ipv6.conf.<interface>.accept_ra=0

  - CVE-2015-3331
    Stephan Mueller discovered that the optimised
    implementation of RFC4106 GCM for x86 processors that
    support AESNI miscalculated buffer addresses in some
    cases. If an IPsec tunnel is configured to use this mode
    (also known as AES-GCM-ESP) this can lead to memory
    corruption and crashes (even without malicious traffic).
    This could potentially also result in remote code
    execution.

  - CVE-2015-3332
    Ben Hutchings discovered that the TCP Fast Open feature
    regressed in Linux 3.16.7-ckt9, resulting in a kernel
    BUG when it is used. This can be used as a local denial
    of service.

  - CVE-2015-3339
    It was found that the execve(2) system call can race
    with inode attribute changes made by chown(2). Although
    chown(2) clears the setuid/setgid bits of a file if it
    changes the respective owner ID, this race condition
    could result in execve(2) setting effective uid/gid to
    the new owner ID, a privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=741667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3332"
  );
  # https://bugs.debian.org/782698
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782698"
  );
  # https://bugs.debian.org/782698
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3237"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 3.2.68-1+deb7u1. The linux package in wheezy is not
affected by CVE-2015-3332.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt9-3~deb8u1 or earlier versions. Additionally,
this version fixes a regression in the xen-netfront driver ( #782698)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.68-1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-x86", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-586", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-686-pae", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-amd64", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armel", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-armhf", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-all-i386", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-amd64", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-common", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-ixp4xx", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-kirkwood", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-orion5x", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-9-versatile", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-586", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-686-pae-dbg", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-amd64-dbg", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-armmp-lpae", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-ixp4xx", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-kirkwood", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-orion5x", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-9-versatile", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-9", reference:"3.16.7-ckt9-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-9-amd64", reference:"3.16.7-ckt9-3~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
