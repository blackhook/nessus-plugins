#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3337. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171861);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_name(english:"Debian DLA-3337-1 : mariadb-10.3 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3337
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1008629");
  # https://security-tracker.debian.org/tracker/source-package/mariadb-10.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb6537b5");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3337");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/mariadb-10.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mariadb-10.3 packages.

For Debian 10 buster, this problem has been fixed in version 1");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadb-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-rocksdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-plugin-tokudb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test-data");
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
    {'release': '10.0', 'prefix': 'libmariadb-dev', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadb-dev-compat', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadb3', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadbclient-dev', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadbd-dev', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libmariadbd19', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-backup', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-client', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-client-10.3', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-client-core-10.3', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-common', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-connect', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-cracklib-password-check', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-gssapi-client', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-gssapi-server', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-mroonga', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-oqgraph', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-rocksdb', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-spider', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-plugin-tokudb', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-server', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-server-10.3', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-server-core-10.3', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-test', 'reference': '1:10.3.38-0+deb10u1'},
    {'release': '10.0', 'prefix': 'mariadb-test-data', 'reference': '1:10.3.38-0+deb10u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadb-dev / libmariadb-dev-compat / libmariadb3 / etc');
}
