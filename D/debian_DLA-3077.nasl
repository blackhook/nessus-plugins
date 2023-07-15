#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3077. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164282);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-31163");

  script_name(english:"Debian DLA-3077-1 : ruby-tzinfo - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by a vulnerability as referenced in the dla-3077
advisory.

  - TZInfo is a Ruby library that provides access to time zone data and allows times to be converted using
    time zone rules. Versions prior to 0.36.1, as well as those prior to 1.2.10 when used with the Ruby data
    source tzinfo-data, are vulnerable to relative path traversal. With the Ruby data source, time zones are
    defined in Ruby files. There is one file per time zone. Time zone files are loaded with `require` on
    demand. In the affected versions, `TZInfo::Timezone.get` fails to validate time zone identifiers
    correctly, allowing a new line character within the identifier. With Ruby version 1.9.3 and later,
    `TZInfo::Timezone.get` can be made to load unintended files with `require`, executing them within the Ruby
    process. Versions 0.3.61 and 1.2.10 include fixes to correctly validate time zone identifiers. Versions
    2.0.0 and later are not vulnerable. Version 0.3.61 can still load arbitrary files from the Ruby load path
    if their name follows the rules for a valid time zone identifier and the file has a prefix of
    `tzinfo/definition` within a directory in the load path. Applications should ensure that untrusted files
    are not placed in a directory on the load path. As a workaround, the time zone identifier can be validated
    before passing to `TZInfo::Timezone.get` by ensuring it matches the regular expression
    `\A[A-Za-z0-9+\-_]+(?:\/[A-Za-z0-9+\-_]+)*\z`. (CVE-2022-31163)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3077");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31163");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ruby-tzinfo");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ruby-tzinfo packages.

For Debian 10 Buster, these problems have been fixed in version 1.2.5-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31163");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-tzinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'ruby-tzinfo', 'reference': '1.2.5-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby-tzinfo');
}
