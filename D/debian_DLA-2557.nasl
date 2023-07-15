#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2557-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146512);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-27815", "CVE-2020-27825", "CVE-2020-27830", "CVE-2020-28374", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2021-20177", "CVE-2021-3347");

  script_name(english:"Debian DLA-2557-1 : linux-4.19 security update");
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

CVE-2020-27815

A flaw was reported in the JFS filesystem code allowing a local
attacker with the ability to set extended attributes to cause a denial
of service.

CVE-2020-27825

Adam 'pi3' Zabrocki reported a use-after-free flaw in the ftrace ring
buffer resizing logic due to a race condition, which could result in
denial of service or information leak.

CVE-2020-27830

Shisong Qin reported a NULL pointer dereference flaw in the Speakup
screen reader core driver.

CVE-2020-28374

David Disseldorp discovered that the LIO SCSI target implementation
performed insufficient checking in certain XCOPY requests. An attacker
with access to a LUN and knowledge of Unit Serial Number assignments
can take advantage of this flaw to read and write to any LIO
backstore, regardless of the SCSI transport settings.

CVE-2020-29568 (XSA-349)

Michael Kurth and Pawel Wieczorkiewicz reported that frontends can
trigger OOM in backends by updating a watched path.

CVE-2020-29569 (XSA-350)

Olivier Benjamin and Pawel Wieczorkiewicz reported a use-after-free
flaw which can be triggered by a block frontend in Linux blkback. A
misbehaving guest can trigger a dom0 crash by continuously connecting
/ disconnecting a block frontend.

CVE-2020-29660

Jann Horn reported a locking inconsistency issue in the tty subsystem
which may allow a local attacker to mount a read-after-free attack
against TIOCGSID.

CVE-2020-29661

Jann Horn reported a locking issue in the tty subsystem which can
result in a use-after-free. A local attacker can take advantage of
this flaw for memory corruption or privilege escalation.

CVE-2020-36158

A buffer overflow flaw was discovered in the mwifiex WiFi driver which
could result in denial of service or the execution of arbitrary code
via a long SSID value.

CVE-2021-3347

It was discovered that PI futexes have a kernel stack use-after-free
during fault handling. An unprivileged user could use this flaw to
crash the kernel (resulting in denial of service) or for privilege
escalation.

CVE-2021-20177

A flaw was discovered in the Linux implementation of string matching
within a packet. A privileged user (with root or CAP_NET_ADMIN) can
take advantage of this flaw to cause a kernel panic when inserting
iptables rules.

For Debian 9 stretch, these problems have been fixed in version
4.19.171-2~deb9u1.

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
    value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00018.html"
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
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3347");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");
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
if (deb_check(release:"9.0", prefix:"linux-config-4.19", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-doc-4.19", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-686-pae", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-amd64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-arm64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armel", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-armhf", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-all-i386", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-amd64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-arm64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-common-rt", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-marvell", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rpi", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-headers-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-686-pae-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-amd64-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-arm64-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-armmp-lpae-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-cloud-amd64-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-marvell-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rpi-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-686-pae-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-amd64-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-arm64-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-image-4.19.0-0.bpo.10-rt-armmp-dbg", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-kbuild-4.19", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-perf-4.19", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-source-4.19", reference:"4.19.171-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"linux-support-4.19.0-0.bpo.10", reference:"4.19.171-2~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
