#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5348-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159268);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2018-13982",
    "CVE-2018-16831",
    "CVE-2021-21408",
    "CVE-2021-26119",
    "CVE-2021-26120",
    "CVE-2021-29454"
  );
  script_xref(name:"USN", value:"5348-1");

  script_name(english:"Ubuntu 18.04 LTS / 21.10 : Smarty vulnerabilities (USN-5348-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 21.10 host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5348-1 advisory.

  - Smarty_Security::isTrustedResourceDir() in Smarty before 3.1.33 is prone to a path traversal vulnerability
    due to insufficient template code sanitization. This allows attackers controlling the executed template
    code to bypass the trusted directory security restriction and read arbitrary files. (CVE-2018-13982)

  - Smarty before 3.1.33-dev-4 allows attackers to bypass the trusted_dir protection mechanism via a
    file:./../ substring in an include statement. (CVE-2018-16831)

  - Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from
    application logic. Prior to versions 3.1.43 and 4.0.3, template authors could run restricted static php
    methods. Users should upgrade to version 3.1.43 or 4.0.3 to receive a patch. (CVE-2021-21408)

  - Smarty before 3.1.39 allows a Sandbox Escape because $smarty.template_object can be accessed in sandbox
    mode. (CVE-2021-26119)

  - Smarty before 3.1.39 allows code injection via an unexpected function name after a {function name=
    substring. (CVE-2021-26120)

  - Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from
    application logic. Prior to versions 3.1.42 and 4.0.2, template authors could run arbitrary PHP code by
    crafting a malicious math string. If a math string was passed through as user provided data to the math
    function, external users could run arbitrary PHP code by crafting a malicious math string. Users should
    upgrade to version 3.1.42 or 4.0.2 to receive a patch. (CVE-2021-29454)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5348-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected smarty3 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smarty3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'smarty3', 'pkgver': '3.1.31+20161214.1.c7d42e4+selfpack1-3ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'smarty3', 'pkgver': '3.1.39-2ubuntu0.21.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'smarty3');
}