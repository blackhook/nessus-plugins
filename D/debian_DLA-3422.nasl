#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3422. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175676);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2023-2454", "CVE-2023-2455");
  script_xref(name:"IAVB", value:"2023-B-0034");

  script_name(english:"Debian DLA-3422-1 : postgresql-11 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3422 advisory.

  - CREATE SCHEMA ... schema_element defeats protective search_path changesmore details (CVE-2023-2454)

  - Row security policies disregard user ID changes after inliningmore details (CVE-2023-2455)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/postgresql-11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e0872ee");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3422");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2455");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/postgresql-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade the postgresql-11 packages.

For Debian 10 buster, these problems have been fixed in version 11.20-0+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plperl-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython3-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-pltcl-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-server-dev-11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'libecpg-compat3', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libecpg-dev', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libecpg6', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libpgtypes3', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libpq-dev', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libpq5', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-11', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-client-11', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-doc-11', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-plperl-11', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-plpython-11', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-plpython3-11', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-pltcl-11', 'reference': '11.20-0+deb10u1'},
    {'release': '10.0', 'prefix': 'postgresql-server-dev-11', 'reference': '11.20-0+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecpg-compat3 / libecpg-dev / libecpg6 / libpgtypes3 / libpq-dev / etc');
}
