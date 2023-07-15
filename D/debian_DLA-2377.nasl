#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2377-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140932);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/05");

  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19870", "CVE-2018-19871", "CVE-2018-19872", "CVE-2018-19873", "CVE-2020-17507");

  script_name(english:"Debian DLA-2377-1 : qt4-x11 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were fixed in qt4-x11, the legacy version of
the Qt toolkit.

CVE-2018-15518

Double-free or corruption in QXmlStreamReader during parsing of a
specially crafted illegal XML document.

CVE-2018-19869

A malformed SVG image causes a segmentation fault.

CVE-2018-19870

A malformed GIF image causes a NULL pointer dereference in QGifHandler
resulting in a segmentation fault.

CVE-2018-19871

Uncontrolled Resource Consumption in QTgaFile.

CVE-2018-19872

A malformed PPM image causes a crash.

CVE-2018-19873

QBmpHandler segfault on malformed BMP file.

CVE-2020-17507

Buffer over-read in the XBM parser.

For Debian 9 stretch, these problems have been fixed in version
4:4.8.7+dfsg-11+deb9u1.

We recommend that you upgrade your qt4-x11 packages.

For the detailed security status of qt4-x11 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/qt4-x11

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/qt4-x11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/qt4-x11"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-declarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-declarative-folderlistmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-declarative-gestures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-declarative-particles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-declarative-shaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-designer-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-opengl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-phonon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-qt3support-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-script-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-scripttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-ibase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-sqlite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-sql-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-xmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt4-xmlpatterns-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqtdbus4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qdbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-demos-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-linguist-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-qmlviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-qtconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtcore4-l10n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/29");
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
if (deb_check(release:"9.0", prefix:"libqt4-dbg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-dbus", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-declarative", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-declarative-folderlistmodel", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-declarative-gestures", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-declarative-particles", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-declarative-shaders", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-designer", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-designer-dbg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-dev", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-dev-bin", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-help", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-network", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-opengl", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-opengl-dev", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-phonon", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-qt3support", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-qt3support-dbg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-script", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-script-dbg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-scripttools", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql-ibase", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql-mysql", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql-odbc", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql-psql", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql-sqlite", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql-sqlite2", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-sql-tds", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-svg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-test", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-xml", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-xmlpatterns", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt4-xmlpatterns-dbg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqtcore4", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqtdbus4", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqtgui4", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qdbus", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-bin-dbg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-default", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-demos", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-demos-dbg", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-designer", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-dev-tools", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-doc", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-doc-html", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-linguist-tools", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-qmake", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-qmlviewer", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt4-qtconfig", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qtcore4-l10n", reference:"4:4.8.7+dfsg-11+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
