#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3057. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162504);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/23");

  script_cve_id("CVE-2021-38562");

  script_name(english:"Debian DLA-3057-1 : request-tracker4 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-3057
advisory.

  - Best Practical Request Tracker (RT) 4.2 before 4.2.17, 4.4 before 4.4.5, and 5.0 before 5.0.2 allows
    sensitive information disclosure via a timing attack against lib/RT/REST2/Middleware/Auth.pm.
    (CVE-2021-38562)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3057");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38562");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/request-tracker4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the request-tracker4 packages.

For Debian 9 Stretch, these problems have been fixed in version 4.4.1-3+deb9u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-db-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rt4-standalone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

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
    {'release': '9.0', 'prefix': 'request-tracker4', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-apache2', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-clients', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-db-mysql', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-db-postgresql', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-db-sqlite', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-doc-html', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-fcgi', 'reference': '4.4.1-3+deb9u4'},
    {'release': '9.0', 'prefix': 'rt4-standalone', 'reference': '4.4.1-3+deb9u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'request-tracker4 / rt4-apache2 / rt4-clients / rt4-db-mysql / etc');
}
