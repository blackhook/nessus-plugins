#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3285. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170889);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/07");

  script_cve_id("CVE-2020-16093", "CVE-2020-36659");

  script_name(english:"Debian DLA-3285-1 : libapache-session-browseable-perl - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3285 advisory.

  - In LemonLDAP::NG (aka lemonldap-ng) through 2.0.8, validity of the X.509 certificate is not checked by
    default when connecting to remote LDAP backends, because the default configuration of the Net::LDAPS
    module for Perl is used. (CVE-2020-16093)

  - In Apache::Session::Browseable before 1.3.6, validity of the X.509 certificate is not checked by default
    when connecting to remote LDAP backends, because the default configuration of the Net::LDAPS module for
    Perl is used. NOTE: this can, for example, be fixed in conjunction with the CVE-2020-16093 fix.
    (CVE-2020-36659)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/libapache-session-browseable-perl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c4ea425");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3285");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-16093");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36659");
  # https://packages.debian.org/source/buster/libapache-session-browseable-perl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0ecabc9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libapache-session-browseable-perl packages.

For Debian 10 buster, this problem has been fixed in version 1.3.0-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16093");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-36659");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-session-browseable-perl");
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
    {'release': '10.0', 'prefix': 'libapache-session-browseable-perl', 'reference': '1.3.0-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache-session-browseable-perl');
}
