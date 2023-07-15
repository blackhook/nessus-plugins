#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2857. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156321);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/27");

  script_cve_id("CVE-2017-18359");

  script_name(english:"Debian DLA-2857-1 : postgis - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2857
advisory.

  - PostGIS 2.x before 2.3.3, as used with PostgreSQL, allows remote attackers to cause a denial of service
    via crafted ST_AsX3D function input, as demonstrated by an abnormal server termination for SELECT
    ST_AsX3D('LINESTRING EMPTY'); because empty geometries are mishandled. (CVE-2017-18359)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/postgis");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2857");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-18359");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/postgis");
  script_set_attribute(attribute:"solution", value:
"Upgrade the postgis packages.

For Debian 9 stretch, this problem has been fixed in version 2.3.1+dfsg-2+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18359");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwgeom-2.3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwgeom-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgis-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgis-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.6-postgis-2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.6-postgis-2.3-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.6-postgis-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'liblwgeom-2.3-0', 'reference': '2.3.1+dfsg-2+deb9u1'},
    {'release': '9.0', 'prefix': 'liblwgeom-dev', 'reference': '2.3.1+dfsg-2+deb9u1'},
    {'release': '9.0', 'prefix': 'postgis', 'reference': '2.3.1+dfsg-2+deb9u1'},
    {'release': '9.0', 'prefix': 'postgis-doc', 'reference': '2.3.1+dfsg-2+deb9u1'},
    {'release': '9.0', 'prefix': 'postgis-gui', 'reference': '2.3.1+dfsg-2+deb9u1'},
    {'release': '9.0', 'prefix': 'postgresql-9.6-postgis-2.3', 'reference': '2.3.1+dfsg-2+deb9u1'},
    {'release': '9.0', 'prefix': 'postgresql-9.6-postgis-2.3-scripts', 'reference': '2.3.1+dfsg-2+deb9u1'},
    {'release': '9.0', 'prefix': 'postgresql-9.6-postgis-scripts', 'reference': '2.3.1+dfsg-2+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liblwgeom-2.3-0 / liblwgeom-dev / postgis / postgis-doc / postgis-gui / etc');
}
