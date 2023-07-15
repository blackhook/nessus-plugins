#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2262-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137887);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id(
    "CVE-2020-13361",
    "CVE-2020-13362",
    "CVE-2020-13765",
    "CVE-2020-1983"
  );
  script_xref(name:"IAVB", value:"2020-B-0041-S");

  script_name(english:"Debian DLA-2262-1 : qemu security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were fixed in qemu, a fast processor emulator.

CVE-2020-1983

slirp: Fix use-after-free in ip_reass().

CVE-2020-13361

es1370_transfer_audio in hw/audio/es1370.c allowed guest OS users to
trigger an out-of-bounds access during an es1370_write() operation.

CVE-2020-13362

megasas_lookup_frame in hw/scsi/megasas.c had an out-of-bounds read
via a crafted reply_queue_head field from a guest OS user.

CVE-2020-13765

hw/core/loader: Fix possible crash in rom_copy().

For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u15.

We recommend that you upgrade your qemu packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00032.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/qemu");
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13765");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (deb_check(release:"8.0", prefix:"qemu", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-guest-agent", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-kvm", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-arm", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-common", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-mips", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-misc", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-ppc", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-sparc", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-x86", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-binfmt", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-static", reference:"1:2.1+dfsg-12+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-utils", reference:"1:2.1+dfsg-12+deb8u15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
