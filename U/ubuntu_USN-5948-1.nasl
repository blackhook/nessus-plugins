#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5948-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172504);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2023-23934", "CVE-2023-25577");
  script_xref(name:"USN", value:"5948-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Werkzeug vulnerabilities (USN-5948-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5948-1 advisory.

  - Werkzeug is a comprehensive WSGI web application library. Browsers may allow nameless cookies that look
    like `=value` instead of `key=value`. A vulnerable browser may allow a compromised application on an
    adjacent subdomain to exploit this to set a cookie like `=__Host-test=bad` for another subdomain. Werkzeug
    prior to 2.2.3 will parse the cookie `=__Host-test=bad` as __Host-test=bad`. If a Werkzeug application is
    running next to a vulnerable or malicious subdomain which sets such a cookie using a vulnerable browser,
    the Werkzeug application will see the bad cookie value but the valid cookie key. The issue is fixed in
    Werkzeug 2.2.3. (CVE-2023-23934)

  - Werkzeug is a comprehensive WSGI web application library. Prior to version 2.2.3, Werkzeug's multipart
    form data parser will parse an unlimited number of parts, including file parts. Parts can be a small
    amount of bytes, but each requires CPU time to parse and may use more memory as Python data. If a request
    can be made to an endpoint that accesses `request.data`, `request.form`, `request.files`, or
    `request.get_data(parse_form_data=False)`, it can cause unexpectedly high resource usage. This allows an
    attacker to cause a denial of service by sending crafted multipart data to an endpoint that will parse it.
    The amount of CPU time required can block worker processes from handling legitimate requests. The amount
    of RAM required can trigger an out of memory kill of the process. Unlimited file parts can use up memory
    and file handles. If many concurrent requests are sent continuously, this can exhaust or kill all
    available workers. Version 2.2.3 contains a patch for this issue. (CVE-2023-25577)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5948-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-werkzeug and / or python3-werkzeug packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-werkzeug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-werkzeug");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'python-werkzeug', 'pkgver': '0.10.4+dfsg1-1ubuntu1.2+esm1'},
    {'osver': '16.04', 'pkgname': 'python3-werkzeug', 'pkgver': '0.10.4+dfsg1-1ubuntu1.2+esm1'},
    {'osver': '18.04', 'pkgname': 'python-werkzeug', 'pkgver': '0.14.1+dfsg1-1ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'python3-werkzeug', 'pkgver': '0.14.1+dfsg1-1ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'python3-werkzeug', 'pkgver': '0.16.1+dfsg1-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'python3-werkzeug', 'pkgver': '2.0.2+dfsg1-1ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'python3-werkzeug', 'pkgver': '2.0.2+dfsg1-3ubuntu0.22.10.1'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-werkzeug / python3-werkzeug');
}
