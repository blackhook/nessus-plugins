#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2347-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140046);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2019-20839", "CVE-2020-14397", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405");

  script_name(english:"Debian DLA-2347-1 : libvncserver security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several minor vulnerabilities have been discovered in libvncserver, a
server and client implementation of the VNC protocol.

CVE-2019-20839

libvncclient/sockets.c in LibVNCServer had a buffer overflow via a
long socket filename.

CVE-2020-14397

libvncserver/rfbregion.c has a NULL pointer dereference.

CVE-2020-14399

Byte-aligned data was accessed through uint32_t pointers in
libvncclient/rfbproto.c.

NOTE: This issue has been disputed by third parties; there
is reportedly 'no trust boundary crossed'.

CVE-2020-14400

Byte-aligned data was accessed through uint16_t pointers in
libvncserver/translate.c.

NOTE: This issue has been disputed by third parties. There
is no known path of exploitation or cross of a trust
boundary.

CVE-2020-14401

libvncserver/scale.c had a pixel_value integer overflow.

CVE-2020-14402

libvncserver/corre.c allowed out-of-bounds access via encodings.

CVE-2020-14403

libvncserver/hextile.c allowed out-of-bounds access via encodings.

CVE-2020-14404

libvncserver/rre.c allowed out-of-bounds access via encodings.

CVE-2020-14405

libvncclient/rfbproto.c did not limit TextChat size.

For Debian 9 stretch, these problems have been fixed in version
0.9.11+dfsg-1.3~deb9u5.

We recommend that you upgrade your libvncserver packages.

For the detailed security status of libvncserver please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libvncserver

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libvncserver"
  );
  # https://security-tracker.debian.org/tracker/source-package/libvncserver
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b930abb4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14401");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncclient1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver1-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");
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
if (deb_check(release:"9.0", prefix:"libvncclient1", reference:"0.9.11+dfsg-1.3~deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libvncclient1-dbg", reference:"0.9.11+dfsg-1.3~deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libvncserver-config", reference:"0.9.11+dfsg-1.3~deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libvncserver-dev", reference:"0.9.11+dfsg-1.3~deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libvncserver1", reference:"0.9.11+dfsg-1.3~deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libvncserver1-dbg", reference:"0.9.11+dfsg-1.3~deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
