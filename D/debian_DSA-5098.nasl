#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5098. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158857);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/22");

  script_cve_id("CVE-2022-26661", "CVE-2022-26662");

  script_name(english:"Debian DSA-5098-1 : tryton-server - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5098 advisory.

  - An XXE issue was discovered in Tryton Application Platform (Server) 5.x through 5.0.45, 6.x through
    6.0.15, and 6.1.x and 6.2.x through 6.2.5, and Tryton Application Platform (Command Line Client (proteus))
    5.x through 5.0.11, 6.x through 6.0.4, and 6.1.x and 6.2.x through 6.2.1. An authenticated user can make
    the server parse a crafted XML SEPA file to access arbitrary files on the system. (CVE-2022-26661)

  - An XML Entity Expansion (XEE) issue was discovered in Tryton Application Platform (Server) 5.x through
    5.0.45, 6.x through 6.0.15, and 6.1.x and 6.2.x through 6.2.5, and Tryton Application Platform (Command
    Line Client (proteus)) 5.x through 5.0.11, 6.x through 6.0.4, and 6.1.x and 6.2.x through 6.2.1. An
    unauthenticated user can send a crafted XML-RPC message to consume all the resources of the server.
    (CVE-2022-26662)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/tryton-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09d52eb3");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26662");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/tryton-server");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/tryton-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade the tryton-server packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.0.33-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26661");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tryton-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tryton-server-doc");
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
    {'release': '10.0', 'prefix': 'tryton-server', 'reference': '5.0.4-2+deb10u1'},
    {'release': '10.0', 'prefix': 'tryton-server-doc', 'reference': '5.0.4-2+deb10u1'},
    {'release': '11.0', 'prefix': 'tryton-server', 'reference': '5.0.33-2+deb11u1'},
    {'release': '11.0', 'prefix': 'tryton-server-doc', 'reference': '5.0.33-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tryton-server / tryton-server-doc');
}
