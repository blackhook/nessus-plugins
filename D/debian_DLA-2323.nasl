#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2323-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139551);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id("CVE-2019-18814", "CVE-2019-18885", "CVE-2019-20810", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-12655", "CVE-2020-12771", "CVE-2020-13974", "CVE-2020-15393");

  script_name(english:"Debian DLA-2323-1 : linux-4.19 new package");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Linux 4.19 has been packaged for Debian 9 as linux-4.19. This provides
a supported upgrade path for systems that currently use kernel
packages from the 'stretch-backports' suite.

There is no need to upgrade systems using Linux 4.9, as that kernel
version will also continue to be supported in the LTS period.

This backport does not include the following binary packages :

hyperv-daemons libbpf-dev libbpf4.19 libcpupower-dev libcpupower1
liblockdep-dev liblockdep4.19 linux-compiler-gcc-6-arm
linux-compiler-gcc-6-x86 linux-cpupower linux-libc-dev lockdep usbip

Older versions of most of those are built from the linux source
package in Debian 9.

The kernel images and modules will not be signed for use on systems
with Secure Boot enabled, as there is no support for this in Debian 9.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or information leak.

CVE-2019-18814

Navid Emamdoost reported a potential use-after-free in the AppArmor
security module, in the case that audit rule initialisation fails. The
security impact of this is unclear.

CVE-2019-18885

The 'bobfuzzer' team discovered that crafted Btrfs volumes could
trigger a crash (oops). An attacker able to mount such a volume could
use this to cause a denial of service.

CVE-2019-20810

A potential memory leak was discovered in the go7007 media driver. The
security impact of this is unclear.

CVE-2020-10766

Anthony Steinhauser reported a flaw in the mitigation for Speculative
Store Bypass (CVE-2018-3639) on x86 CPUs. A local user could use this
to temporarily disable SSB mitigation in other users' tasks. If those
other tasks run sandboxed code, this would allow that code to read
sensitive information in the same process but outside the sandbox.

CVE-2020-10767

Anthony Steinhauser reported a flaw in the mitigation for Spectre
variant 2 (CVE-2017-5715) on x86 CPUs. Depending on which other
mitigations the CPU supports, the kernel might not use IBPB to
mitigate Spectre variant 2 in user-space. A local user could use this
to read sensitive information from other users' processes.

CVE-2020-10768

Anthony Steinhauser reported a flaw in the mitigation for Spectre
variant 2 (CVE-2017-5715) on x86 CPUs. After a task force- disabled
indirect branch speculation through prctl(), it could still re-enable
it later, so it was not possible to override a program that explicitly
enabled it.

CVE-2020-12655

Zheng Bin reported that crafted XFS volumes could trigger a system
hang. An attacker able to mount such a volume could use this to cause
a denial of service.

CVE-2020-12771

Zhiqiang Liu reported a bug in the bcache block driver that could lead
to a system hang. The security impact of this is unclear.

CVE-2020-13974

Kyungtae Kim reported a potential integer overflow in the vt (virtual
terminal) driver. The security impact of this is unclear.

CVE-2020-15393

Kyungtae Kim reported a memory leak in the usbtest driver. The
security impact of this is unclear.

For Debian 9 'Stretch', these problems have been fixed in version
4.19.132-1~deb9u1. This update additionally fixes Debian bugs #958300,
#960493, #962254, #963493, #964153, #964480, and #965365; and includes
many more bug fixes from stable updates 4.19.119-4.19.132 inclusive.

We recommend that you upgrade your linux-4.19 packages.

For the detailed security status of linux-4.19 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/linux-4.19

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/linux-4.19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux-4.19"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-0.bpo.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-0.bpo.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-0.bpo.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"linux-config-4.19", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.19", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686-pae", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-amd64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-arm64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armel", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armhf", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-i386", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-amd64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-arm64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common-rt", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-marvell", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rpi", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp-dbg", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.19", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.19", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.19", reference:"4.19.132-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.19.0-0.bpo.10", reference:"4.19.132-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
