#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2887. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156818);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/19");

  script_cve_id("CVE-2018-19052");

  script_name(english:"Debian DLA-2887-1 : lighttpd - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2887
advisory.

  - An issue was discovered in mod_alias_physical_handler in mod_alias.c in lighttpd before 1.4.50. There is
    potential ../ path traversal of a single directory above an alias target, with a specific mod_alias
    configuration where the matched alias lacks a trailing '/' character, but the alias target filesystem path
    does have a trailing '/' character. (CVE-2018-19052)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/lighttpd");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2887");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-19052");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/lighttpd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the lighttpd packages.

For Debian 9 stretch, this problem has been fixed in version 1.4.45-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-mysql-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-trigger-b4-dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-webdav");
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
    {'release': '9.0', 'prefix': 'lighttpd', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-doc', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-authn-gssapi', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-authn-ldap', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-authn-mysql', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-cml', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-geoip', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-magnet', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-mysql-vhost', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-trigger-b4-dl', 'reference': '1.4.45-1+deb9u1'},
    {'release': '9.0', 'prefix': 'lighttpd-mod-webdav', 'reference': '1.4.45-1+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lighttpd / lighttpd-doc / lighttpd-mod-authn-gssapi / etc');
}
