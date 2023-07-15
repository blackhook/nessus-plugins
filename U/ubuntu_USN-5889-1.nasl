#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5889-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171952);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

  script_cve_id(
    "CVE-2019-6777",
    "CVE-2019-6990",
    "CVE-2019-6991",
    "CVE-2019-6992",
    "CVE-2019-7325",
    "CVE-2019-7326",
    "CVE-2019-7327",
    "CVE-2019-7328",
    "CVE-2019-7329",
    "CVE-2019-7330",
    "CVE-2019-7331",
    "CVE-2019-7332",
    "CVE-2022-29806"
  );
  script_xref(name:"USN", value:"5889-1");

  script_name(english:"Ubuntu 16.04 ESM / 20.04 ESM / 22.04 ESM : ZoneMinder vulnerabilities (USN-5889-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 20.04 ESM / 22.04 ESM host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-5889-1 advisory.

  - An issue was discovered in ZoneMinder v1.32.3. Reflected XSS exists in web/skins/classic/views/plugin.php
    via the zm/index.php?view=plugin pl parameter. (CVE-2019-6777)

  - A stored-self XSS exists in web/skins/classic/views/zones.php of ZoneMinder through 1.32.3, allowing an
    attacker to execute HTML or JavaScript code in a vulnerable field via a crafted Zone NAME to the
    index.php?view=zones&action=zoneImage&mid=1 URI. (CVE-2019-6990)

  - A classic Stack-based buffer overflow exists in the zmLoadUser() function in zm_user.cpp of the zmu binary
    in ZoneMinder through 1.32.3, allowing an unauthenticated attacker to execute code via a long username.
    (CVE-2019-6991)

  - A stored-self XSS exists in web/skins/classic/views/controlcaps.php of ZoneMinder through 1.32.3, allowing
    an attacker to execute HTML or JavaScript code in a vulnerable field via a long NAME or PROTOCOL to the
    index.php?view=controlcaps URI. (CVE-2019-6992)

  - Reflected Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3, as multiple views under
    web/skins/classic/views insecurely utilize $_REQUEST['PHP_SELF'], without applying any proper filtration.
    (CVE-2019-7325)

  - Self - Stored Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3, allowing an attacker to
    execute HTML or JavaScript code via a vulnerable 'Host' parameter value in the view console (console.php)
    because proper filtration is omitted. This relates to the index.php?view=monitor Host Name field.
    (CVE-2019-7326)

  - Reflected Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3, allowing an attacker to execute
    HTML or JavaScript code via a vulnerable 'scale' parameter value in the view frame (frame.php) because
    proper filtration is omitted. (CVE-2019-7327)

  - Reflected Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3, allowing an attacker to execute
    HTML or JavaScript code via a vulnerable 'scale' parameter value in the view frame (frame.php) via
    /js/frame.js.php because proper filtration is omitted. (CVE-2019-7328)

  - Reflected Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3, as the form action on multiple
    views utilizes $_SERVER['PHP_SELF'] insecurely, mishandling any arbitrary input appended to the webroot
    URL, without any proper filtration, leading to XSS. (CVE-2019-7329)

  - Reflected Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3, allowing an attacker to execute
    HTML or JavaScript code via a vulnerable 'show' parameter value in the view frame (frame.php) because
    proper filtration is omitted. (CVE-2019-7330)

  - Self - Stored Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3 while editing an existing
    monitor field named signal check color (monitor.php). There exists no input validation or output
    filtration, leaving it vulnerable to HTML Injection and an XSS attack. (CVE-2019-7331)

  - Reflected Cross Site Scripting (XSS) exists in ZoneMinder through 1.32.3, allowing an attacker to execute
    HTML or JavaScript code via a vulnerable 'eid' (aka Event ID) parameter value in the view download
    (download.php) because proper filtration is omitted. (CVE-2019-7332)

  - ZoneMinder before 1.36.13 allows remote code execution via an invalid language. Ability to create a debug
    log file at an arbitrary pathname contributes to exploitability. (CVE-2022-29806)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5889-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected zoneminder package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29806");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ZoneMinder Language Settings Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zoneminder");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04|20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'zoneminder', 'pkgver': '1.29.0+dfsg-1ubuntu2+esm1'},
    {'osver': '20.04', 'pkgname': 'zoneminder', 'pkgver': '1.32.3-2ubuntu2+esm1'},
    {'osver': '22.04', 'pkgname': 'zoneminder', 'pkgver': '1.36.12+dfsg1-1ubuntu0.1~esm1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'zoneminder');
}
