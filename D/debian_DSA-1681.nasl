#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1681. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35036);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3528", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4618", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5134", "CVE-2008-5182", "CVE-2008-5300");
  script_bugtraq_id(31634, 31903, 32093, 32154, 32289);
  script_xref(name:"DSA", value:"1681");

  script_name(english:"Debian DSA-1681-1 : linux-2.6.24 - denial of service/privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-3528
    Eugene Teo reported a local DoS issue in the ext2 and
    ext3 filesystems. Local users who have been granted the
    privileges necessary to mount a filesystem would be able
    to craft a corrupted filesystem that causes the kernel
    to output error messages in an infinite loop.

  - CVE-2008-4554
    Milos Szeredi reported that the usage of splice() on
    files opened with O_APPEND allows users to write to the
    file at arbitrary offsets, enabling a bypass of possible
    assumed semantics of the O_APPEND flag.

  - CVE-2008-4576
    Vlad Yasevich reported an issue in the SCTP subsystem
    that may allow remote users to cause a local DoS by
    triggering a kernel oops.

  - CVE-2008-4618
    Wei Yongjun reported an issue in the SCTP subsystem that
    may allow remote users to cause a local DoS by
    triggering a kernel panic.

  - CVE-2008-4933
    Eric Sesterhenn reported a local DoS issue in the
    hfsplus filesystem. Local users who have been granted
    the privileges necessary to mount a filesystem would be
    able to craft a corrupted filesystem that causes the
    kernel to overrun a buffer, resulting in a system oops
    or memory corruption.

  - CVE-2008-4934
    Eric Sesterhenn reported a local DoS issue in the
    hfsplus filesystem. Local users who have been granted
    the privileges necessary to mount a filesystem would be
    able to craft a corrupted filesystem that results in a
    kernel oops due to an unchecked return value.

  - CVE-2008-5025
    Eric Sesterhenn reported a local DoS issue in the hfs
    filesystem. Local users who have been granted the
    privileges necessary to mount a filesystem would be able
    to craft a filesystem with a corrupted catalog name
    length, resulting in a system oops or memory corruption.

  - CVE-2008-5029
    Andrea Bittau reported a DoS issue in the unix socket
    subsystem that allows a local user to cause memory
    corruption, resulting in a kernel panic.

  - CVE-2008-5134
    Johannes Berg reported a remote DoS issue in the
    libertas wireless driver, which can be triggered by a
    specially crafted beacon/probe response.

  - CVE-2008-5182
    Al Viro reported race conditions in the inotify
    subsystem that may allow local users to acquire elevated
    privileges.

  - CVE-2008-5300
    Dann Frazier reported a DoS condition that allows local
    users to cause the out of memory handler to kill off
    privileged processes or trigger soft lockups due to a
    starvation issue in the unix socket subsystem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2008/dsa-1681"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6.24 packages.

For the stable distribution (etch), these problems have been fixed in
version 2.6.24-6~etchnhalf.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 264, 287, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.24", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-alpha", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-amd64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-arm", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-hppa", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-i386", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-ia64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mips", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-powerpc", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-s390", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-all-sparc", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-common", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-footbridge", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-iop32x", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-ixp4xx", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-486", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-4kc-malta", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-5kc-malta", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-686-bigmem", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-generic", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-alpha-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-amd64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-footbridge", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-iop32x", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-itanium", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-ixp4xx", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-mckinley", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-miboot", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-powerpc64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r4k-ip22", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-r5k-ip32", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390-tape", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-s390x", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.24-etchnhalf.1-sparc64-smp", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.24", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.24", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.24", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.24-etchnhalf.1", reference:"2.6.24-6~etchnhalf.7")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.24", reference:"2.6.24-6~etchnhalf.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
