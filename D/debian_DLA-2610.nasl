#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2610-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148254);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/21");

  script_cve_id("CVE-2020-27170", "CVE-2020-27171", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-28660", "CVE-2021-3348", "CVE-2021-3428");

  script_name(english:"Debian DLA-2610-1 : linux-4.19 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to the execution of arbitrary code, privilege escalation,
denial of service, or information leaks.

CVE-2020-27170, CVE-2020-27171

Piotr Krysiuk discovered flaws in the BPF subsystem's checks for
information leaks through speculative execution. A local user could
use these to obtain sensitive information from kernel memory.

CVE-2021-3348

ADlab of venustech discovered a race condition in the nbd block driver
that can lead to a use-after-free. A local user with access to an nbd
block device could use this to cause a denial of service (crash or
memory corruption) or possibly for privilege escalation.

CVE-2021-3428

Wolfgang Frisch reported a potential integer overflow in the ext4
filesystem driver. A user permitted to mount arbitrary filesystem
images could use this to cause a denial of service (crash).

CVE-2021-26930 (XSA-365)

Olivier Benjamin, Norbert Manthey, Martin Mazein, and Jan H.
Sch&ouml;nherr discovered that the Xen block backend driver
(xen-blkback) did not handle grant mapping errors correctly. A
malicious guest could exploit this bug to cause a denial of service
(crash), or possibly an information leak or privilege escalation,
within the domain running the backend, which is typically dom0.

CVE-2021-26931 (XSA-362), CVE-2021-26932 (XSA-361), CVE-2021-28038
(XSA-367)

Jan Beulich discovered that the Xen support code and various Xen
backend drivers did not handle grant mapping errors correctly. A
malicious guest could exploit these bugs to cause a denial of service
(crash) within the domain running the backend, which is typically
dom0.

CVE-2021-27363

Adam Nichols reported that the iSCSI initiator subsystem did not
properly restrict access to transport handle attributes in sysfs. On a
system acting as an iSCSI initiator, this is an information leak to
local users and makes it easier to exploit CVE-2021-27364.

CVE-2021-27364

Adam Nichols reported that the iSCSI initiator subsystem did not
properly restrict access to its netlink management interface. On a
system acting as an iSCSI initiator, a local user could use these to
cause a denial of service (disconnection of storage) or possibly for
privilege escalation.

CVE-2021-27365

Adam Nichols reported that the iSCSI initiator subsystem did not
correctly limit the lengths of parameters or 'passthrough PDUs' sent
through its netlink management interface. On a system acting as an
iSCSI initiator, a local user could use these to leak the contents of
kernel memory, to cause a denial of service (kernel memory corruption
or crash), and probably for privilege escalation.

CVE-2021-28660

It was discovered that the rtl8188eu WiFi driver did not correctly
limit the length of SSIDs copied into scan results. An attacker within
WiFi range could use this to cause a denial of service (crash or
memory corruption) or possibly to execute code on a vulnerable system.

For Debian 9 stretch, these problems have been fixed in version
4.19.181-1~deb9u1. This update additionally fixes Debian bug #983595,
and includes many more bug fixes from stable updates 4.19.172-4.19.181
inclusive.

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
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00035.html"
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
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"linux-config-4.19", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.19", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686-pae", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-amd64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-arm64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armel", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armhf", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-i386", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-amd64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-arm64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common-rt", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-marvell", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rpi", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp-dbg", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.19", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.19", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.19", reference:"4.19.181-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.19.0-0.bpo.10", reference:"4.19.181-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
