#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2895. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157047);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-3481", "CVE-2021-45930");

  script_name(english:"Debian DLA-2895-1 : qt4-x11 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2895 advisory.

  - Qt SVG in Qt 5.0.0 through 5.15.2 and 6.0.0 through 6.2.1 has an out-of-bounds write in
    QtPrivate::QCommonArrayOps<QPainterPath::Element>::growAppend (called from QPainterPath::addPath and
    QPathClipper::intersect). (CVE-2021-45930)

  - A flaw was found in Qt. An out-of-bounds read vulnerability was found in QRadialFetchSimd in
    qt/qtbase/src/gui/painting/qdrawhelper_p.h in Qt/Qtbase. While rendering and displaying a crafted Scalable
    Vector Graphics (SVG) file this flaw may lead to an unauthorized memory access. The highest threat from
    this vulnerability is to data confidentiality and the application availability. (CVE-2021-3481)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=986798");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qt4-x11");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2895");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3481");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45930");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/qt4-x11");
  script_set_attribute(attribute:"solution", value:
"Upgrade the qt4-x11 packages.

For Debian 9 stretch, these problems have been fixed in version 4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45930");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/24");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libqt4-dbg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-dbus', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-declarative', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-declarative-folderlistmodel', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-declarative-gestures', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-declarative-particles', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-declarative-shaders', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-designer', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-designer-dbg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-dev', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-dev-bin', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-help', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-network', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-opengl', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-opengl-dev', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-phonon', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-qt3support', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-qt3support-dbg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-script', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-script-dbg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-scripttools', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql-ibase', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql-mysql', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql-odbc', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql-psql', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql-sqlite', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql-sqlite2', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-sql-tds', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-svg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-test', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-xml', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-xmlpatterns', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqt4-xmlpatterns-dbg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqtcore4', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqtdbus4', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'libqtgui4', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qdbus', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-bin-dbg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-default', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-demos', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-demos-dbg', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-designer', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-dev-tools', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-doc', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-doc-html', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-linguist-tools', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-qmake', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-qmlviewer', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qt4-qtconfig', 'reference': '4:4.8.7+dfsg-11+deb9u3'},
    {'release': '9.0', 'prefix': 'qtcore4-l10n', 'reference': '4:4.8.7+dfsg-11+deb9u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libqt4-dbg / libqt4-dbus / libqt4-declarative / etc');
}
