#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5067. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157380);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/15");

  script_cve_id("CVE-2021-41816", "CVE-2021-41817", "CVE-2021-41819");

  script_name(english:"Debian DSA-5067-1 : ruby2.7 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5067 advisory.

  - CGI::Cookie.parse in Ruby through 2.6.8 mishandles security prefixes in cookie names. This also affects
    the CGI gem through 0.3.0 for Ruby. (CVE-2021-41819)

  - CGI.escape_html in Ruby before 2.7.5 and 3.x before 3.0.3 has an integer overflow and resultant buffer
    overflow via a long string on platforms (such as Windows) where size_t and long have different numbers of
    bytes. This also affects the CGI gem before 0.3.1 for Ruby. (CVE-2021-41816)

  - Date.parse in the date gem through 3.2.0 for Ruby allows ReDoS (regular expression Denial of Service) via
    a long string. The fixed versions are 3.2.1, 3.1.2, 3.0.2, and 2.0.1. (CVE-2021-41817)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ruby2.7");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5067");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41816");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41817");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41819");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ruby2.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ruby2.7 packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.7.4-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.7-doc");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libruby2.7', 'reference': '2.7.4-1+deb11u1'},
    {'release': '11.0', 'prefix': 'ruby2.7', 'reference': '2.7.4-1+deb11u1'},
    {'release': '11.0', 'prefix': 'ruby2.7-dev', 'reference': '2.7.4-1+deb11u1'},
    {'release': '11.0', 'prefix': 'ruby2.7-doc', 'reference': '2.7.4-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libruby2.7 / ruby2.7 / ruby2.7-dev / ruby2.7-doc');
}
