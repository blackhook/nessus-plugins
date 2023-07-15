#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5066. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157378);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-28965",
    "CVE-2021-31799",
    "CVE-2021-31810",
    "CVE-2021-32066",
    "CVE-2021-41817",
    "CVE-2021-41819"
  );

  script_name(english:"Debian DSA-5066-1 : ruby2.5 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5066 advisory.

  - The REXML gem before 3.2.5 in Ruby before 2.6.7, 2.7.x before 2.7.3, and 3.x before 3.0.1 does not
    properly address XML round-trip issues. An incorrect document can be produced after parsing and
    serializing. (CVE-2021-28965)

  - In RDoc 3.11 through 6.x before 6.3.1, as distributed with Ruby through 3.0.1, it is possible to execute
    arbitrary code via | and tags in a filename. (CVE-2021-31799)

  - An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. A malicious FTP
    server can use the PASV response to trick Net::FTP into connecting back to a given IP address and port.
    This potentially makes curl extract information about services that are otherwise private and not
    disclosed (e.g., the attacker can conduct port scans and service banner extractions). (CVE-2021-31810)

  - An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. Net::IMAP does
    not raise an exception when StartTLS fails with an an unknown response, which might allow man-in-the-
    middle attackers to bypass the TLS protections by leveraging a network position between the client and the
    registry to block the StartTLS command, aka a StartTLS stripping attack. (CVE-2021-32066)

  - Date.parse in the date gem through 3.2.0 for Ruby allows ReDoS (regular expression Denial of Service) via
    a long string. The fixed versions are 3.2.1, 3.1.2, 3.0.2, and 2.0.1. (CVE-2021-41817)

  - CGI::Cookie.parse in Ruby through 2.6.8 mishandles security prefixes in cookie names. This also affects
    the CGI gem through 0.3.0 for Ruby. (CVE-2021-41819)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ruby2.5");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5066");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31799");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32066");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41817");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41819");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ruby2.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ruby2.5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32066");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-41819");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.5-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libruby2.5', 'reference': '2.5.5-3+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby2.5', 'reference': '2.5.5-3+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby2.5-dev', 'reference': '2.5.5-3+deb10u4'},
    {'release': '10.0', 'prefix': 'ruby2.5-doc', 'reference': '2.5.5-3+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libruby2.5 / ruby2.5 / ruby2.5-dev / ruby2.5-doc');
}
