#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2417-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142052);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-25211", "CVE-2020-25643", "CVE-2020-25645");

  script_name(english:"Debian DLA-2417-1 : linux-4.19 security update");
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
denial of service or information leaks.

CVE-2020-12351

Andy Nguyen discovered a flaw in the Bluetooth implementation in the
way L2CAP packets with A2MP CID are handled. A remote attacker in
short distance knowing the victim's Bluetooth device address can send
a malicious l2cap packet and cause a denial of service or possibly
arbitrary code execution with kernel privileges.

CVE-2020-12352

Andy Nguyen discovered a flaw in the Bluetooth implementation. Stack
memory is not properly initialised when handling certain AMP packets.
A remote attacker in short distance knowing the victim's Bluetooth
device address address can retrieve kernel stack information.

CVE-2020-25211

A flaw was discovered in netfilter subsystem. A local attacker able to
inject conntrack Netlink configuration can cause a denial of service.

CVE-2020-25643

ChenNan Of Chaitin Security Research Lab discovered a flaw in the
hdlc_ppp module. Improper input validation in the ppp_cp_parse_cr()
function may lead to memory corruption and information disclosure.

CVE-2020-25645

A flaw was discovered in the interface driver for GENEVE encapsulated
traffic when combined with IPsec. If IPsec is configured to encrypt
traffic for the specific UDP port used by the GENEVE tunnel, tunneled
data isn't correctly routed over the encrypted link and sent
unencrypted instead.

For Debian 9 stretch, these problems have been fixed in version
4.19.152-1~deb9u1.

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
    value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00028.html"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"linux-config-4.19", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.19", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686-pae", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-amd64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-arm64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armel", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armhf", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-i386", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-amd64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-arm64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common-rt", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-marvell", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rpi", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp-dbg", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.19", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.19", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.19", reference:"4.19.152-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.19.0-0.bpo.10", reference:"4.19.152-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
