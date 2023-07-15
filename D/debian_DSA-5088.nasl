#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5088. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158585);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/04");

  script_cve_id("CVE-2021-36740", "CVE-2022-23959");

  script_name(english:"Debian DSA-5088-1 : varnish - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5088 advisory.

  - Varnish Cache, with HTTP/2 enabled, allows request smuggling and VCL authorization bypass via a large
    Content-Length header for a POST request. This affects Varnish Enterprise 6.0.x before 6.0.8r3, and
    Varnish Cache 5.x and 6.x before 6.5.2, 6.6.x before 6.6.1, and 6.0 LTS before 6.0.8. (CVE-2021-36740)

  - In Varnish Cache before 6.6.2 and 7.x before 7.0.2, Varnish Cache 6.0 LTS before 6.0.10, and and Varnish
    Enterprise (Cache Plus) 4.1.x before 4.1.11r6 and 6.0.x before 6.0.9r4, request smuggling can occur for
    HTTP/1 connections. (CVE-2022-23959)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=991040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/varnish");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36740");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23959");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/varnish");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/varnish");
  script_set_attribute(attribute:"solution", value:
"Upgrade the varnish packages.

For the stable distribution (bullseye), these problems have been fixed in version 6.5.1-1+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvarnishapi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvarnishapi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:varnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:varnish-doc");
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
    {'release': '10.0', 'prefix': 'libvarnishapi-dev', 'reference': '6.1.1-1+deb10u3'},
    {'release': '10.0', 'prefix': 'libvarnishapi2', 'reference': '6.1.1-1+deb10u3'},
    {'release': '10.0', 'prefix': 'varnish', 'reference': '6.1.1-1+deb10u3'},
    {'release': '10.0', 'prefix': 'varnish-doc', 'reference': '6.1.1-1+deb10u3'},
    {'release': '11.0', 'prefix': 'libvarnishapi-dev', 'reference': '6.5.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libvarnishapi2', 'reference': '6.5.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'varnish', 'reference': '6.5.1-1+deb11u2'},
    {'release': '11.0', 'prefix': 'varnish-doc', 'reference': '6.5.1-1+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvarnishapi-dev / libvarnishapi2 / varnish / varnish-doc');
}
