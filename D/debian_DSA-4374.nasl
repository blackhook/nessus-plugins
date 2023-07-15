#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4374. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121426);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873");
  script_xref(name:"DSA", value:"4374");

  script_name(english:"Debian DSA-4374-1 : qtbase-opensource-src - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues were discovered in qtbase-opensource-src, a
cross-platform C++ application framework, which could lead to
denial-of-service via application crash. Additionally, this update
fixes a problem affecting vlc, where it would start without a GUI."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=907139"
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
    value:"https://www.debian.org/security/2019/dsa-4374"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qtbase-opensource-src packages.

For the stable distribution (stretch), these problems have been fixed
in version 5.7.1+dfsg-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qtbase-opensource-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libqt5concurrent5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5core5a", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5dbus5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5gui5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5network5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5opengl5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5opengl5-dev", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5printsupport5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-ibase", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-mysql", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-odbc", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-psql", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-sqlite", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5sql5-tds", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5test5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5widgets5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libqt5xml5", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt5-default", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt5-gtk-platformtheme", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qt5-qmake", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-dev", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-dev-tools", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-doc", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-doc-html", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-examples", reference:"5.7.1+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"qtbase5-private-dev", reference:"5.7.1+dfsg-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
