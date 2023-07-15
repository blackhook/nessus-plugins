#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5956-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172589);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id(
    "CVE-2016-10033",
    "CVE-2016-10045",
    "CVE-2017-5223",
    "CVE-2017-11503",
    "CVE-2018-19296",
    "CVE-2020-13625",
    "CVE-2021-3603"
  );
  script_xref(name:"USN", value:"5956-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM : PHPMailer vulnerabilities (USN-5956-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 ESM / 22.04 ESM host has a package installed that is affected by
multiple vulnerabilities as referenced in the USN-5956-1 advisory.

  - The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to
    pass extra parameters to the mail command and consequently execute arbitrary code via a \ (backslash
    double quote) in a crafted Sender property. (CVE-2016-10033)

  - The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass extra parameters to
    the mail command and consequently execute arbitrary code by leveraging improper interaction between the
    escapeshellarg function and internal escaping performed in the mail function in PHP. NOTE: this
    vulnerability exists because of an incorrect fix for CVE-2016-10033. (CVE-2016-10045)

  - PHPMailer 5.2.23 has XSS in the From Email Address and To Email Address fields of code_generator.php.
    (CVE-2017-11503)

  - An issue was discovered in PHPMailer before 5.2.22. PHPMailer's msgHTML method applies transformations to
    an HTML document to make it usable as an email message body. One of the transformations is to convert
    relative image URLs into attachments using a script-provided base directory. If no base directory is
    provided, it resolves to /, meaning that relative image URLs get treated as absolute local file paths and
    added as attachments. To form a remote vulnerability, the msgHTML method must be called, passed an
    unfiltered, user-supplied HTML document, and must not set a base directory. (CVE-2017-5223)

  - PHPMailer before 5.2.27 and 6.x before 6.0.6 is vulnerable to an object injection attack. (CVE-2018-19296)

  - PHPMailer before 6.1.6 contains an output escaping bug when the name of a file attachment contains a
    double quote character. This can result in the file type being misinterpreted by the receiver or any mail
    relay processing the message. (CVE-2020-13625)

  - PHPMailer 6.4.1 and earlier contain a vulnerability that can result in untrusted code being called (if
    such code is injected into the host project's scope by other means). If the $patternselect parameter to
    validateAddress() is set to 'php' (the default, defined by PHPMailer::$validator), and the global
    namespace contains a function called php, it will be called in preference to the built-in validator of the
    same name. Mitigated in PHPMailer 6.5.0 by denying the use of simple strings as validator function names.
    (CVE-2021-3603)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5956-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libphp-phpmailer package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10045");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WordPress PHPMailer Host Header Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp-phpmailer");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libphp-phpmailer', 'pkgver': '5.2.14+dfsg-1ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'libphp-phpmailer', 'pkgver': '5.2.14+dfsg-2.3+deb9u2ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'libphp-phpmailer', 'pkgver': '6.0.6-0.1ubuntu0.1~esm1'},
    {'osver': '22.04', 'pkgname': 'libphp-phpmailer', 'pkgver': '6.2.0-2ubuntu0.1~esm1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libphp-phpmailer');
}
