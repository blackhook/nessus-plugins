#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5482-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172054);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/02");

  script_cve_id(
    "CVE-2021-44118",
    "CVE-2021-44120",
    "CVE-2021-44122",
    "CVE-2021-44123"
  );
  script_xref(name:"USN", value:"5482-2");

  script_name(english:"Ubuntu 20.04 LTS : SPIP vulnerabilities (USN-5482-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5482-2 advisory.

  - SPIP 4.0.0 is affected by a Cross Site Scripting (XSS) vulnerability. To exploit the vulnerability, a
    visitor must browse to a malicious SVG file. The vulnerability allows an authenticated attacker to inject
    malicious code running on the client side into web pages visited by other users (stored XSS).
    (CVE-2021-44118)

  - SPIP 4.0.0 is affected by a Cross Site Scripting (XSS) vulnerability in ecrire/public/interfaces.php,
    adding the function safehtml to the vulnerable fields. An editor is able to modify his personal
    information. If the editor has an article written and available, when a user goes to the public site and
    wants to read the author's information, the malicious code will be executed. The Who are you and
    Website Name fields are vulnerable. (CVE-2021-44120)

  - SPIP 4.0.0 is affected by a Cross Site Request Forgery (CSRF) vulnerability in
    ecrire/public/aiguiller.php, ecrire/public/balises.php, ecrire/balise/formulaire_.php. To exploit the
    vulnerability, a visitor must visit a malicious website which redirects to the SPIP website. It is also
    possible to combine XSS vulnerabilities in SPIP 4.0.0 to exploit it. The vulnerability allows an
    authenticated attacker to execute malicious code without the knowledge of the user on the website (CSRF).
    (CVE-2021-44122)

  - SPIP 4.0.0 is affected by a remote command execution vulnerability. To exploit the vulnerability, an
    attacker must craft a malicious picture with a double extension, upload it and then click on it to execute
    it. (CVE-2021-44123)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5482-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected spip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44122");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-44123");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:spip");
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
if (! preg(pattern:"^(20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'spip', 'pkgver': '3.2.7-1ubuntu0.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spip');
}
