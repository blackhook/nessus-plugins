#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1715-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122879);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-18249", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12896", "CVE-2018-13053", "CVE-2018-13096", "CVE-2018-13097", "CVE-2018-13100", "CVE-2018-13406", "CVE-2018-14610", "CVE-2018-14611", "CVE-2018-14612", "CVE-2018-14613", "CVE-2018-14614", "CVE-2018-14616", "CVE-2018-15471", "CVE-2018-16862", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-19407", "CVE-2018-3639", "CVE-2018-5391", "CVE-2018-5848", "CVE-2018-6554");

  script_name(english:"Debian DLA-1715-1 : linux-4.9 security update (Spectre)");
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

CVE-2017-18249

A race condition was discovered in the disk space allocator of F2FS. A
user with access to an F2FS volume could use this to cause a denial of
service or other security impact.

CVE-2018-1128, CVE-2018-1129

The cephx authentication protocol used by Ceph was susceptible to
replay attacks, and calculated signatures incorrectly. These
vulnerabilities in the server required changes to authentication that
are incompatible with existing clients. The kernel's client code has
now been updated to be compatible with the fixed server.

CVE-2018-3639 (SSB)

Multiple researchers have discovered that Speculative Store Bypass
(SSB), a feature implemented in many processors, could be used to read
sensitive information from another context. In particular, code in a
software sandbox may be able to read sensitive information from
outside the sandbox. This issue is also known as Spectre variant 4.

This update adds a further mitigation for this issue in the
eBPF (Extended Berkeley Packet Filter) implementation.

CVE-2018-5391 (FragmentSmack)

Juha-Matti Tilli discovered a flaw in the way the Linux kernel handled
reassembly of fragmented IPv4 and IPv6 packets. A remote attacker can
take advantage of this flaw to trigger time and calculation expensive
fragment reassembly algorithms by sending specially crafted packets,
leading to remote denial of service.

This was previously mitigated by reducing the default limits
on memory usage for incomplete fragmented packets. This
update replaces that mitigation with a more complete fix.

CVE-2018-5848

The wil6210 wifi driver did not properly validate lengths in scan and
connection requests, leading to a possible buffer overflow. On systems
using this driver, a local user with the CAP_NET_ADMIN capability
could use this for denial of service (memory corruption or crash) or
potentially for privilege escalation.

CVE-2018-12896, CVE-2018-13053

Team OWL337 reported possible integer overflows in the POSIX timer
implementation. These might have some security impact.

CVE-2018-13096, CVE-2018-13097, CVE-2018-13100, CVE-2018-14614,
CVE-2018-14616

Wen Xu from SSLab at Gatech reported that crafted F2FS volumes could
trigger a crash (BUG, Oops, or division by zero) and/or out-of-bounds
memory access. An attacker able to mount such a volume could use this
to cause a denial of service or possibly for privilege escalation.

CVE-2018-13406

Dr Silvio Cesare of InfoSect reported a potential integer overflow in
the uvesafb driver. A user with permission to access such a device
might be able to use this for denial of service or privilege
escalation.

CVE-2018-14610, CVE-2018-14611, CVE-2018-14612, CVE-2018-14613

Wen Xu from SSLab at Gatech reported that crafted Btrfs volumes could
trigger a crash (Oops) and/or out-of-bounds memory access. An attacker
able to mount such a volume could use this to cause a denial of
service or possibly for privilege escalation.

CVE-2018-15471 ((XSA-270)

Felix Wilhelm of Google Project Zero discovered a flaw in the hash
handling of the xen-netback Linux kernel module. A malicious or buggy
frontend may cause the (usually privileged) backend to make out of
bounds memory accesses, potentially resulting in privilege escalation,
denial of service, or information leaks.

https://xenbits.xen.org/xsa/advisory-270.html

CVE-2018-16862

Vasily Averin and Pavel Tikhomirov from Virtuozzo Kernel Team
discovered that the cleancache memory management feature did not
invalidate cached data for deleted files. On Xen guests using the tmem
driver, local users could potentially read data from other users'
deleted files if they were able to create new files on the same
volume.

CVE-2018-17972

Jann Horn reported that the /proc/*/stack files in procfs leaked
sensitive data from the kernel. These files are now only readable by
users with the CAP_SYS_ADMIN capability (usually only root)

CVE-2018-18281

Jann Horn reported a race condition in the virtual memory manager that
can result in a process briefly having access to memory after it is
freed and reallocated. A local user could possibly exploit this for
denial of service (memory corruption) or for privilege escalation.

CVE-2018-18690

Kanda Motohiro reported that XFS did not correctly handle some xattr
(extended attribute) writes that require changing the disk format of
the xattr. A user with access to an XFS volume could use this for
denial of service.

CVE-2018-18710

It was discovered that the cdrom driver does not correctly validate
the parameter to the CDROM_SELECT_DISC ioctl. A user with access to a
cdrom device could use this to read sensitive information from the
kernel or to cause a denial of service (crash).

CVE-2018-19407

Wei Wu reported a potential crash (Oops) in the KVM implementation for
x86 processors. A user with access to /dev/kvm could use this for
denial of service.

For Debian 8 'Jessie', these problems have been fixed in version
4.9.144-3.1~deb8u1. This version also includes fixes for Debian bugs
#890034, #896911, #907581, #915229, and #915231; and other fixes
included in upstream stable updates.

We recommend that you upgrade your linux-4.9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux-4.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://xenbits.xen.org/xsa/advisory-270.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13406");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-arm", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-4.9", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686-pae", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-amd64", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armel", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armhf", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-i386", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-amd64", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common-rt", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-marvell", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64-dbg", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-marvell", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-kbuild-4.9", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-4.9", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-perf-4.9", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-4.9", reference:"4.9.144-3.1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-4.9.0-0.bpo.7", reference:"4.9.144-3.1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
