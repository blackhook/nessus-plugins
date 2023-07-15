#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5397-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160318);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-22576",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776"
  );
  script_xref(name:"USN", value:"5397-1");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : curl vulnerabilities (USN-5397-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5397-1 advisory.

  - A insufficiently protected credentials vulnerability in fixed in curl 7.83.0 might leak authentication or
    cookie header data on HTTP redirects to the same host but another port number. (CVE-2022-27776)

  - An improper authentication vulnerability exists in curl 7.33.0 to and including 7.82.0 which might allow
    reuse OAUTH2-authenticated connections without properly making sure that the connection was authenticated
    with the same credentials as set for this transfer. This affects SASL-enabled protocols: SMPTP(S),
    IMAP(S), POP3(S) and LDAP(S) (openldap only). (CVE-2022-22576)

  - An insufficiently protected credentials vulnerability exists in curl 4.9 to and include curl 7.82.0 are
    affected that could allow an attacker to extract credentials when follows HTTP(S) redirects is used with
    authentication could leak credentials to other services that exist on different protocols or port numbers.
    (CVE-2022-27774)

  - An information disclosure vulnerability exists in curl 7.65.0 to 7.82.0 are vulnerable that by using an
    IPv6 address that was in the connection pool but with a different zone id it could reuse a connection
    instead. (CVE-2022-27775)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5397-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22576");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl4-openssl-dev");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'curl', 'pkgver': '7.58.0-2ubuntu3.17'},
    {'osver': '18.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.58.0-2ubuntu3.17'},
    {'osver': '18.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.58.0-2ubuntu3.17'},
    {'osver': '18.04', 'pkgname': 'libcurl4', 'pkgver': '7.58.0-2ubuntu3.17'},
    {'osver': '18.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.58.0-2ubuntu3.17'},
    {'osver': '18.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.58.0-2ubuntu3.17'},
    {'osver': '18.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.58.0-2ubuntu3.17'},
    {'osver': '20.04', 'pkgname': 'curl', 'pkgver': '7.68.0-1ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.68.0-1ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.68.0-1ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'libcurl4', 'pkgver': '7.68.0-1ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.68.0-1ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.68.0-1ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.68.0-1ubuntu2.10'},
    {'osver': '21.10', 'pkgname': 'curl', 'pkgver': '7.74.0-1.3ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.74.0-1.3ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcurl3-nss', 'pkgver': '7.74.0-1.3ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcurl4', 'pkgver': '7.74.0-1.3ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.74.0-1.3ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.74.0-1.3ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.74.0-1.3ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'curl', 'pkgver': '7.81.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcurl3-gnutls', 'pkgver': '7.81.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcurl3-nss', 'pkgver': '7.81.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcurl4', 'pkgver': '7.81.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcurl4-gnutls-dev', 'pkgver': '7.81.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcurl4-nss-dev', 'pkgver': '7.81.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libcurl4-openssl-dev', 'pkgver': '7.81.0-1ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl / libcurl3-gnutls / libcurl3-nss / libcurl4 / etc');
}
