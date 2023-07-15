#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2092-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133412);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-0569");

  script_name(english:"Debian DLA-2092-1 : qtbase-opensource-src security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In Qt5's plugin loader code as found in qtbase-opensource-src, it was
possible to (side-)load plugins from 'the' local folder in addition to
a system-widely defined library path.

For Debian 8 'Jessie', this problem has been fixed in version
5.3.2+dfsg-4+deb8u4.

We recommend that you upgrade your qtbase-opensource-src packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/02/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/qtbase-opensource-src"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5core5a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5dbus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5opengl5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5opengl5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5printsupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5sql5-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqt5xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt5-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt5-qmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-dev-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-dev-tools-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-examples-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase5-private-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/03");
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
if (deb_check(release:"8.0", prefix:"libqt5concurrent5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5core5a", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5dbus5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5gui5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5network5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5opengl5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5opengl5-dev", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5printsupport5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5sql5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5sql5-mysql", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5sql5-odbc", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5sql5-psql", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5sql5-sqlite", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5sql5-tds", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5test5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5widgets5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libqt5xml5", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qt5-default", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qt5-qmake", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-dbg", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-dev", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-dev-tools", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-dev-tools-dbg", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-doc-html", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-examples", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-examples-dbg", reference:"5.3.2+dfsg-4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"qtbase5-private-dev", reference:"5.3.2+dfsg-4+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
