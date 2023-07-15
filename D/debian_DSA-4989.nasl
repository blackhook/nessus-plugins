#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4989. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154229);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2021-41990", "CVE-2021-41991");

  script_name(english:"Debian DSA-4989-1 : strongswan - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4989 advisory.

  - The gmp plugin in strongSwan before 5.9.4 has a remote integer overflow via a crafted certificate with an
    RSASSA-PSS signature. For example, this can be triggered by an unrelated self-signed CA certificate sent
    by an initiator. Remote code execution cannot occur. (CVE-2021-41990)

  - The in-memory certificate cache in strongSwan before 5.9.4 has a remote integer overflow upon receiving
    many requests with different certificates to fill the cache and later trigger the replacement of cache
    entries. The code attempts to select a less-often-used cache entry by means of a random number generator,
    but this is not done correctly. Remote code execution might be a slight possibility. (CVE-2021-41991)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/strongswan");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41991");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/strongswan");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/strongswan");
  script_set_attribute(attribute:"solution", value:
"Upgrade the strongswan packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.9.1-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:charon-cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:charon-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcharon-extauth-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcharon-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstrongswan-standard-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-charon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-libcharon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-scepclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-starter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan-swanctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'charon-cmd', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'charon-systemd', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libcharon-extauth-plugins', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libcharon-extra-plugins', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libstrongswan', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libstrongswan-extra-plugins', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libstrongswan-standard-plugins', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan-charon', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan-libcharon', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan-nm', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan-pki', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan-scepclient', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan-starter', 'reference': '5.7.2-1+deb10u1'},
    {'release': '10.0', 'prefix': 'strongswan-swanctl', 'reference': '5.7.2-1+deb10u1'},
    {'release': '11.0', 'prefix': 'charon-cmd', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'charon-systemd', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcharon-extauth-plugins', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libcharon-extra-plugins', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libstrongswan', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libstrongswan-extra-plugins', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libstrongswan-standard-plugins', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan-charon', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan-libcharon', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan-nm', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan-pki', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan-scepclient', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan-starter', 'reference': '5.9.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'strongswan-swanctl', 'reference': '5.9.1-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'charon-cmd / charon-systemd / libcharon-extauth-plugins / etc');
}
