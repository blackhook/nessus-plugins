#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2875. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156576);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/10");

  script_name(english:"Debian DLA-2875-1 : clamav - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2875
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/clamav");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2875");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/clamav");
  script_set_attribute(attribute:"solution", value:
"Upgrade the clamav packages.

For Debian 9 stretch, this problem has been fixed in version 0.103.4+dfsg-0+deb9u1.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'clamav', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-base', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-daemon', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-docs', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-freshclam', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-milter', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-testfiles', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamdscan', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'libclamav-dev', 'reference': '0.103.4+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'libclamav9', 'reference': '0.103.4+dfsg-0+deb9u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav / clamav-base / clamav-daemon / clamav-docs / clamav-freshclam / etc');
}
