#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2623-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148442);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-17380", "CVE-2021-20203", "CVE-2021-20255", "CVE-2021-20257", "CVE-2021-3392", "CVE-2021-3409", "CVE-2021-3416");

  script_name(english:"Debian DLA-2623-1 : qemu security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several security vulnerabilities have been discovered in QEMU, a fast
processor emulator.

CVE-2021-20257

net: e1000: infinite loop while processing transmit descriptors

CVE-2021-20255

A stack overflow via an infinite recursion vulnerability was found in
the eepro100 i8255x device emulator of QEMU. This issue occurs while
processing controller commands due to a DMA reentry issue. This flaw
allows a guest user or process to consume CPU cycles or crash the QEMU
process on the host, resulting in a denial of service.

CVE-2021-20203

An integer overflow issue was found in the vmxnet3 NIC emulator of the
QEMU. It may occur if a guest was to supply invalid values for rx/tx
queue size or other NIC parameters. A privileged guest user may use
this flaw to crash the QEMU process on the host resulting in DoS
scenario.

CVE-2021-3416

A potential stack overflow via infinite loop issue was found in
various NIC emulators of QEMU in versions up to and including 5.2.0.
The issue occurs in loopback mode of a NIC wherein reentrant DMA
checks get bypassed. A guest user/process may use this flaw to consume
CPU cycles or crash the QEMU process on the host resulting in DoS
scenario.

CVE-2021-3416

The patch for CVE-2020-17380/CVE-2020-25085 was found to be
ineffective, thus making QEMU vulnerable to the out-of-bounds
read/write access issues previously found in the SDHCI controller
emulation code. This flaw allows a malicious privileged guest to crash
the QEMU process on the host, resulting in a denial of service or
potential code execution.

For Debian 9 stretch, these problems have been fixed in version
1:2.8+dfsg-6+deb9u14.

We recommend that you upgrade your qemu packages.

For the detailed security status of qemu please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/qemu

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/qemu"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3409");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");
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
if (deb_check(release:"9.0", prefix:"qemu", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-block-extra", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-guest-agent", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-kvm", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-arm", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-common", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-mips", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-misc", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-ppc", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-sparc", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-x86", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-binfmt", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-static", reference:"1:2.8+dfsg-6+deb9u14")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-utils", reference:"1:2.8+dfsg-6+deb9u14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
