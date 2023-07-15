#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3425. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175929);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2023-30608");

  script_name(english:"Debian DLA-3425-1 : sqlparse - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3425
advisory.

  - sqlparse is a non-validating SQL parser module for Python. In affected versions the SQL parser contains a
    regular expression that is vulnerable to ReDoS (Regular Expression Denial of Service). This issue was
    introduced by commit `e75e358`. The vulnerability may lead to Denial of Service (DoS). This issues has
    been fixed in sqlparse 0.4.4 by commit `c457abd5f`. Users are advised to upgrade. There are no known
    workarounds for this issue. (CVE-2023-30608)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1034615");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sqlparse");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3425");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-30608");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/sqlparse");
  script_set_attribute(attribute:"solution", value:
"Upgrade the sqlparse packages.

For Debian 10 buster, this problem has been fixed in version 0.2.4-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pypy-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-sqlparse-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlformat");
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
    {'release': '10.0', 'prefix': 'pypy-sqlparse', 'reference': '0.2.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-sqlparse', 'reference': '0.2.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-sqlparse-doc', 'reference': '0.2.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-sqlparse', 'reference': '0.2.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'sqlformat', 'reference': '0.2.4-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pypy-sqlparse / python-sqlparse / python-sqlparse-doc / etc');
}
