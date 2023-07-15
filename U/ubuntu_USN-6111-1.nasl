#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6111-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176459);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id("CVE-2023-30861");
  script_xref(name:"USN", value:"6111-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 / 23.04 : Flask vulnerability (USN-6111-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 / 23.04 host has a package installed that is affected by a vulnerability
as referenced in the USN-6111-1 advisory.

  - Flask is a lightweight WSGI web application framework. When all of the following conditions are met, a
    response containing data intended for one client may be cached and subsequently sent by the proxy to other
    clients. If the proxy also caches `Set-Cookie` headers, it may send one client's `session` cookie to other
    clients. The severity depends on the application's use of the session and the proxy's behavior regarding
    cookies. The risk depends on all these conditions being met. 1. The application must be hosted behind a
    caching proxy that does not strip cookies or ignore responses with cookies. 2. The application sets
    `session.permanent = True` 3. The application does not access or modify the session at any point during a
    request. 4. `SESSION_REFRESH_EACH_REQUEST` enabled (the default). 5. The application does not set a
    `Cache-Control` header to indicate that a page is private or should not be cached. This happens because
    vulnerable versions of Flask only set the `Vary: Cookie` header when the session is accessed or modified,
    not when it is refreshed (re-sent to update the expiration) without being accessed or modified. This issue
    has been fixed in versions 2.3.2 and 2.2.5. (CVE-2023-30861)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6111-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-flask package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-flask");
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
if (! preg(pattern:"^(20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'python3-flask', 'pkgver': '1.1.1-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'python3-flask', 'pkgver': '2.0.1-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'python3-flask', 'pkgver': '2.0.3-1ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'python3-flask', 'pkgver': '2.2.2-2ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-flask');
}
