#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4617. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133475);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2020-0569", "CVE-2020-0570");
  script_xref(name:"DSA", value:"4617");

  script_name(english:"Debian DSA-4617-1 : qtbase-opensource-src - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two security issues were found in the Qt library, which could result
in plugins and libraries being loaded from the current working
directory, resulting in potential code execution."
  );
  # https://security-tracker.debian.org/tracker/source-package/qtbase-opensource-src
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?daec893f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/qtbase-opensource-src"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/qtbase-opensource-src"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4617"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the qtbase-opensource-src packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 5.7.1+dfsg-3+deb9u2.

For the stable distribution (buster), these problems have been fixed
in version 5.11.3+dfsg1-1+deb10u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase-opensource-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/05");
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
if (deb_check(release:"10.0", prefix:"libqt5concurrent5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5core5a", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5dbus5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5gui5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5network5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5opengl5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5opengl5-dev", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5printsupport5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5sql5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5sql5-ibase", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5sql5-mysql", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5sql5-odbc", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5sql5-psql", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5sql5-sqlite", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5sql5-tds", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5test5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5widgets5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libqt5xml5", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qt5-default", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qt5-flatpak-platformtheme", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qt5-gtk-platformtheme", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qt5-qmake", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qt5-qmake-bin", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qtbase5-dev", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qtbase5-dev-tools", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qtbase5-doc", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qtbase5-doc-html", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qtbase5-examples", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"qtbase5-private-dev", reference:"5.11.3+dfsg1-1+deb10u3")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5concurrent5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5core5a", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5dbus5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5gui5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5network5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5opengl5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5opengl5-dev", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5printsupport5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-ibase", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-mysql", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-odbc", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-psql", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-sqlite", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-tds", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5test5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5widgets5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5xml5", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qt5-default", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qt5-gtk-platformtheme", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qt5-qmake", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-dev", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-dev-tools", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-doc", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-doc-html", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-examples", reference:"5.7.1+dfsg-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-private-dev", reference:"5.7.1+dfsg-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
