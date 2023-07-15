#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2264-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137907);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-20839", "CVE-2020-14397", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405");

  script_name(english:"Debian DLA-2264-1 : libvncserver security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in libVNC (libvncserver
Debian package), an implemenantation of the VNC server and client
protocol.

CVE-2019-20839

libvncclient/sockets.c in LibVNCServer had a buffer overflow via a
long socket filename.

CVE-2020-14397

libvncserver/rfbregion.c had a NULL pointer dereference.

CVE-2020-14399

Byte-aligned data was accessed through uint32_t pointers in
libvncclient/rfbproto.c.

CVE-2020-14400

Byte-aligned data was accessed through uint16_t pointers in
libvncserver/translate.c.

CVE-2020-14401

libvncserver/scale.c had a pixel_value integer overflow.

CVE-2020-14402

libvncserver/corre.c allowed out-of-bounds access via encodings.

CVE-2020-14403

libvncserver/hextile.c allowed out-of-bounds access via encodings.

CVE-2020-14404

libvncserver/rre.c allowed out-of-bounds access via encodings.

CVE-2020-14405

libvncclient/rfbproto.c does not limit TextChat size.

For Debian 8 'Jessie', these problems have been fixed in version
0.9.9+dfsg2-6.1+deb8u8.

We recommend that you upgrade your libvncserver packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvncserver"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncclient0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linuxvnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");
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
if (deb_check(release:"8.0", prefix:"libvncclient0", reference:"0.9.9+dfsg2-6.1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libvncclient0-dbg", reference:"0.9.9+dfsg2-6.1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver-config", reference:"0.9.9+dfsg2-6.1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver-dev", reference:"0.9.9+dfsg2-6.1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver0", reference:"0.9.9+dfsg2-6.1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver0-dbg", reference:"0.9.9+dfsg2-6.1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"linuxvnc", reference:"0.9.9+dfsg2-6.1+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
