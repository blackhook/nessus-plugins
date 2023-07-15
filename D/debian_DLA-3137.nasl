#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3137. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165709);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_cve_id(
    "CVE-2021-22930",
    "CVE-2021-22939",
    "CVE-2021-22940",
    "CVE-2022-21824",
    "CVE-2022-32212"
  );

  script_name(english:"Debian DLA-3137-1 : nodejs - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3137 advisory.

  - Node.js before 16.6.0, 14.17.4, and 12.22.4 is vulnerable to a use after free attack where an attacker
    might be able to exploit the memory corruption, to change process behavior. (CVE-2021-22930)

  - If the Node.js https API was used incorrectly and undefined was in passed for the rejectUnauthorized
    parameter, no error was returned and connections to servers with an expired certificate would have been
    accepted. (CVE-2021-22939)

  - Node.js before 16.6.1, 14.17.5, and 12.22.5 is vulnerable to a use after free attack where an attacker
    might be able to exploit the memory corruption, to change process behavior. (CVE-2021-22940)

  - Due to the formatting logic of the console.table() function it was not safe to allow user controlled
    input to be passed to the properties parameter while simultaneously passing a plain object with at least
    one property as the first parameter, which could be __proto__. The prototype pollution has very limited
    control, in that it only allows an empty string to be assigned to numerical keys of the object
    prototype.Node.js >= 12.22.9, >= 14.18.3, >= 16.13.2, and >= 17.3.1 use a null protoype for the object
    these properties are being assigned to. (CVE-2022-21824)

  - A OS Command Injection vulnerability exists in Node.js versions <14.20.0, <16.16.0, <18.5.0 due to an
    insufficient IsAllowedHost check that can easily be bypassed because IsIPAddress does not properly check
    if an IP address is invalid before making DBS requests allowing rebinding attacks. (CVE-2022-32212)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1004177");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nodejs");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3137");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22939");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22940");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21824");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32212");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/nodejs");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nodejs packages.

For Debian 10 buster, these problems have been fixed in version 10.24.0~dfsg-1~deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnode-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnode64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nodejs-doc");
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
    {'release': '10.0', 'prefix': 'libnode-dev', 'reference': '10.24.0~dfsg-1~deb10u2'},
    {'release': '10.0', 'prefix': 'libnode64', 'reference': '10.24.0~dfsg-1~deb10u2'},
    {'release': '10.0', 'prefix': 'nodejs', 'reference': '10.24.0~dfsg-1~deb10u2'},
    {'release': '10.0', 'prefix': 'nodejs-doc', 'reference': '10.24.0~dfsg-1~deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnode-dev / libnode64 / nodejs / nodejs-doc');
}
