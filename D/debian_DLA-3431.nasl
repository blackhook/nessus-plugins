#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3431. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176213);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/22");

  script_cve_id("CVE-2016-6153", "CVE-2018-8740");

  script_name(english:"Debian DLA-3431-1 : sqlite - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3431 advisory.

  - os_unix.c in SQLite before 3.13.0 improperly implements the temporary directory search algorithm, which
    might allow local users to obtain sensitive information, cause a denial of service (application crash), or
    have unspecified other impact by leveraging use of the current working directory for temporary files.
    (CVE-2016-6153)

  - In SQLite through 3.22.0, databases whose schema is corrupted using a CREATE TABLE AS statement could
    cause a NULL pointer dereference, related to build.c and prepare.c. (CVE-2018-8740)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sqlite");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3431");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-6153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-8740");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/sqlite");
  script_set_attribute(attribute:"solution", value:
"Upgrade the sqlite packages.

For Debian 10 buster, these problems have been fixed in version 2.8.17-15+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libsqlite-tcl', 'reference': '2.8.17-15+deb10u1'},
    {'release': '10.0', 'prefix': 'libsqlite0', 'reference': '2.8.17-15+deb10u1'},
    {'release': '10.0', 'prefix': 'libsqlite0-dev', 'reference': '2.8.17-15+deb10u1'},
    {'release': '10.0', 'prefix': 'sqlite', 'reference': '2.8.17-15+deb10u1'},
    {'release': '10.0', 'prefix': 'sqlite-doc', 'reference': '2.8.17-15+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsqlite-tcl / libsqlite0 / libsqlite0-dev / sqlite / sqlite-doc');
}
