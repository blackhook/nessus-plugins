#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2571-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146677);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id("CVE-2015-8011", "CVE-2017-9214", "CVE-2018-17204", "CVE-2018-17206", "CVE-2020-27827", "CVE-2020-35498");

  script_name(english:"Debian DLA-2571-1 : openvswitch security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several issues have been found in openvswitch, a production quality,
multilayer, software-based, Ethernet virtual switch.

CVE-2020-35498

Denial of service attacks, in which crafted network packets could
cause the packet lookup to ignore network header fields from layers 3
and 4. The crafted network packet is an ordinary IPv4 or IPv6 packet
with Ethernet padding length above 255 bytes. This causes the packet
sanity check to abort parsing header fields after layer 2.

CVE-2020-27827

Denial of service attacks using crafted LLDP packets.

CVE-2018-17206

Buffer over-read issue during BUNDLE action decoding.

CVE-2018-17204

Assertion failure due to not validating information (group type and
command) in OF1.5 decoder.

CVE-2017-9214

Buffer over-read that is caused by an unsigned integer underflow.

CVE-2015-8011

Buffer overflow in the lldp_decode function in daemon/protocols/lldp.c
in lldpd before 0.8.0 allows remote attackers to cause a denial of
service (daemon crash) and possibly execute arbitrary code via vectors
involving large management addresses and TLV boundaries.

For Debian 9 stretch, these problems have been fixed in version
2.6.10-0+deb9u1. This version is a new upstream point release.

We recommend that you upgrade your openvswitch packages.

For the detailed security status of openvswitch please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/openvswitch

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openvswitch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openvswitch"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9214");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-testcontroller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-controller-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"openvswitch-common", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-dbg", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-dev", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-ipsec", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-pki", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-switch", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-test", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-testcontroller", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openvswitch-vtep", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ovn-central", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ovn-common", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ovn-controller-vtep", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ovn-docker", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ovn-host", reference:"2.6.10-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-openvswitch", reference:"2.6.10-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
