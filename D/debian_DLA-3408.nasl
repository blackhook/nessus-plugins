#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3408. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174967);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2017-17742",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-25613",
    "CVE-2021-31810",
    "CVE-2021-32066",
    "CVE-2023-28755",
    "CVE-2023-28756"
  );

  script_name(english:"Debian DLA-3408-1 : jruby - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3408 advisory.

  - Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before 2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1 allows
    an HTTP Response Splitting attack. An attacker can inject a crafted key and value into an HTTP response
    for the HTTP server of WEBrick. (CVE-2017-17742)

  - WEBrick::HTTPAuth::DigestAuth in Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 has a
    regular expression Denial of Service cause by looping/backtracking. A victim must expose a WEBrick server
    that uses DigestAuth to the Internet or a untrusted network. (CVE-2019-16201)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows HTTP Response Splitting. If a
    program using WEBrick inserts untrusted input into the response header, an attacker can exploit it to
    insert a newline character to split a header, and inject malicious content to deceive clients. NOTE: this
    issue exists because of an incomplete fix for CVE-2017-17742, which addressed the CRLF vector, but did not
    address an isolated CR or an isolated LF. (CVE-2019-16254)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows code injection if the first
    argument (aka the command argument) to Shell#[] or Shell#test in lib/shell.rb is untrusted data. An
    attacker can exploit this to call an arbitrary Ruby method. (CVE-2019-16255)

  - An issue was discovered in Ruby through 2.5.8, 2.6.x through 2.6.6, and 2.7.x through 2.7.1. WEBrick, a
    simple HTTP server bundled with Ruby, had not checked the transfer-encoding header value rigorously. An
    attacker may potentially exploit this issue to bypass a reverse proxy (which also has a poor header
    check), which may lead to an HTTP Request Smuggling attack. (CVE-2020-25613)

  - An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. A malicious FTP
    server can use the PASV response to trick Net::FTP into connecting back to a given IP address and port.
    This potentially makes curl extract information about services that are otherwise private and not
    disclosed (e.g., the attacker can conduct port scans and service banner extractions). (CVE-2021-31810)

  - An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. Net::IMAP does
    not raise an exception when StartTLS fails with an an unknown response, which might allow man-in-the-
    middle attackers to bypass the TLS protections by leveraging a network position between the client and the
    registry to block the StartTLS command, aka a StartTLS stripping attack. (CVE-2021-32066)

  - A ReDoS issue was discovered in the URI component through 0.12.0 in Ruby through 3.2.1. The URI parser
    mishandles invalid URLs that have specific characters. It causes an increase in execution time for parsing
    strings to URI objects. The fixed versions are 0.12.1, 0.11.1, 0.10.2 and 0.10.0.1. (CVE-2023-28755)

  - A ReDoS issue was discovered in the Time component through 0.2.1 in Ruby through 3.2.1. The Time parser
    mishandles invalid URLs that have specific characters. It causes an increase in execution time for parsing
    strings to Time objects. The fixed versions are 0.1.1 and 0.2.2. (CVE-2023-28756)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=972230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/jruby");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3408");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-17742");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16201");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16254");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16255");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25613");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32066");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28755");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28756");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/jruby");
  script_set_attribute(attribute:"solution", value:
"Upgrade the jruby packages.

For Debian 10 buster, these problems have been fixed in version 9.1.17.0-3+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16255");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jruby");
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
    {'release': '10.0', 'prefix': 'jruby', 'reference': '9.1.17.0-3+deb10u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jruby');
}
