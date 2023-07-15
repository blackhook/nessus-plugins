#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5040. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156651);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2022-22707");

  script_name(english:"Debian DSA-5040-1 : lighttpd - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5040
advisory.

  - In lighttpd 1.4.46 through 1.4.63, the mod_extforward_Forwarded function of the mod_extforward plugin has
    a stack-based buffer overflow (4 bytes representing -1), as demonstrated by remote denial of service
    (daemon crash) in a non-default configuration. The non-default configuration requires handling of the
    Forwarded header in a somewhat unusual manner. Also, a 32-bit system is much more likely to be affected
    than a 64-bit system. (CVE-2022-22707)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/lighttpd");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22707");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/lighttpd");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/lighttpd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the lighttpd packages.

For the stable distribution (bullseye), this problem has been fixed in version 1.4.59-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-authn-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-maxminddb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-mbedtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-mysql-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-trigger-b4-dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-vhostdb-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-vhostdb-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-mod-wolfssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-modules-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-modules-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-modules-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd-modules-mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'lighttpd', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-doc', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-authn-gssapi', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-authn-ldap', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-authn-mysql', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-authn-pam', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-authn-sasl', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-cml', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-deflate', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-geoip', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-magnet', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-maxminddb', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-mbedtls', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-mysql-vhost', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-nss', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-openssl', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-trigger-b4-dl', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-vhostdb-dbi', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-vhostdb-pgsql', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-webdav', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-mod-wolfssl', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-modules-dbi', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-modules-ldap', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-modules-lua', 'reference': '1.4.53-4+deb10u2'},
    {'release': '10.0', 'prefix': 'lighttpd-modules-mysql', 'reference': '1.4.53-4+deb10u2'},
    {'release': '11.0', 'prefix': 'lighttpd', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-doc', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-authn-gssapi', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-authn-ldap', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-authn-mysql', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-authn-pam', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-authn-sasl', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-cml', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-deflate', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-geoip', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-magnet', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-maxminddb', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-mbedtls', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-mysql-vhost', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-nss', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-openssl', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-trigger-b4-dl', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-vhostdb-dbi', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-vhostdb-pgsql', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-webdav', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-mod-wolfssl', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-modules-dbi', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-modules-ldap', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-modules-lua', 'reference': '1.4.59-1+deb11u1'},
    {'release': '11.0', 'prefix': 'lighttpd-modules-mysql', 'reference': '1.4.59-1+deb11u1'}
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
