#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5177. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162762);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-24851",
    "CVE-2022-31084",
    "CVE-2022-31085",
    "CVE-2022-31086",
    "CVE-2022-31087",
    "CVE-2022-31088"
  );

  script_name(english:"Debian DSA-5177-1 : ldap-account-manager - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5177 advisory.

  - LDAP Account Manager (LAM) is an open source web frontend for managing entries stored in an LDAP
    directory. The profile editor tool has an edit profile functionality, the parameters on this page are not
    properly sanitized and hence leads to stored XSS attacks. An authenticated user can store XSS payloads in
    the profiles, which gets triggered when any other user try to access the edit profile page. The pdf editor
    tool has an edit pdf profile functionality, the logoFile parameter in it is not properly sanitized and an
    user can enter relative paths like
    ../../../../../../../../../../../../../usr/share/icons/hicolor/48x48/apps/gvim.png via tools like
    burpsuite. Later when a pdf is exported using the edited profile the pdf icon has the image on that
    path(if image is present). Both issues require an attacker to be able to login to LAM admin interface. The
    issue is fixed in version 7.9.1. (CVE-2022-24851)

  - LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings)
    stored in an LDAP directory. In versions prior to 8.0 There are cases where LAM instantiates objects from
    arbitrary classes. An attacker can inject the first constructor argument. This can lead to code execution
    if non-LAM classes are instantiated that execute code during object creation. This issue has been fixed in
    version 8.0. (CVE-2022-31084)

  - LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings)
    stored in an LDAP directory. In versions prior to 8.0 the session files include the LDAP user name and
    password in clear text if the PHP OpenSSL extension is not installed or encryption is disabled by
    configuration. This issue has been fixed in version 8.0. Users unable to upgrade should install the PHP
    OpenSSL extension and make sure session encryption is enabled in LAM main configuration. (CVE-2022-31085)

  - LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings)
    stored in an LDAP directory. In versions prior to 8.0 incorrect regular expressions allow to upload PHP
    scripts to config/templates/pdf. This vulnerability could lead to a Remote Code Execution if the
    /config/templates/pdf/ directory is accessible for remote users. This is not a default configuration of
    LAM. This issue has been fixed in version 8.0. There are no known workarounds for this issue.
    (CVE-2022-31086)

  - LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings)
    stored in an LDAP directory. In versions prior to 8.0 the tmp directory, which is accessible by /lam/tmp/,
    allows interpretation of .php (and .php5/.php4/.phpt/etc) files. An attacker capable of writing files
    under www-data privileges can write a web-shell into this directory, and gain a Code Execution on the
    host. This issue has been fixed in version 8.0. Users unable to upgrade should disallow executing PHP
    scripts in (/var/lib/ldap-account-manager/)tmp directory. (CVE-2022-31087)

  - LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings)
    stored in an LDAP directory. In versions prior to 8.0 the user name field at login could be used to
    enumerate LDAP data. This is only the case for LDAP search configuration. This issue has been fixed in
    version 8.0. (CVE-2022-31088)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/ldap-account-manager
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e38a554");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5177");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24851");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31086");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31087");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31088");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ldap-account-manager");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ldap-account-manager packages.

For the stable distribution (bullseye), these problems have been fixed in version 8.0.1-0+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31087");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31086");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldap-account-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldap-account-manager-lamdaemon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ldap-account-manager', 'reference': '8.0.1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'ldap-account-manager-lamdaemon', 'reference': '8.0.1-0+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ldap-account-manager / ldap-account-manager-lamdaemon');
}
