#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5903-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172024);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2022-22707", "CVE-2022-41556");
  script_xref(name:"USN", value:"5903-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : lighttpd vulnerabilities (USN-5903-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5903-1 advisory.

  - In lighttpd 1.4.46 through 1.4.63, the mod_extforward_Forwarded function of the mod_extforward plugin has
    a stack-based buffer overflow (4 bytes representing -1), as demonstrated by remote denial of service
    (daemon crash) in a non-default configuration. The non-default configuration requires handling of the
    Forwarded header in a somewhat unusual manner. Also, a 32-bit system is much more likely to be affected
    than a 64-bit system. (CVE-2022-22707)

  - A resource leak in gw_backend.c in lighttpd 1.4.56 through 1.4.66 could lead to a denial of service
    (connection-slot exhaustion) after a large amount of anomalous TCP behavior by clients. It is related to
    RDHUP mishandling in certain HTTP/1.1 chunked situations. Use of mod_fastcgi is, for example, affected.
    This is fixed in 1.4.67. (CVE-2022-41556)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5903-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22707");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-authn-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-authn-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-authn-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-maxminddb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-mbedtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-trigger-b4-dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-vhostdb-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-vhostdb-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-mod-wolfssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-modules-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-modules-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-modules-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lighttpd-modules-mysql");
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
if (! preg(pattern:"^(20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'lighttpd', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-dev', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-authn-gssapi', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-authn-pam', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-authn-sasl', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-cml', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-geoip', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-magnet', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-maxminddb', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-trigger-b4-dl', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-vhostdb-dbi', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-vhostdb-pgsql', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-mod-webdav', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-modules-ldap', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '20.04', 'pkgname': 'lighttpd-modules-mysql', 'pkgver': '1.4.55-1ubuntu1.20.04.2'},
    {'osver': '22.04', 'pkgname': 'lighttpd', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-authn-gssapi', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-authn-pam', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-authn-sasl', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-deflate', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-geoip', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-maxminddb', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-mbedtls', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-nss', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-openssl', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-trigger-b4-dl', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-vhostdb-pgsql', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-webdav', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-mod-wolfssl', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-modules-dbi', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-modules-ldap', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-modules-lua', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'lighttpd-modules-mysql', 'pkgver': '1.4.63-1ubuntu3.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-authn-gssapi', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-authn-pam', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-authn-sasl', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-deflate', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-gnutls', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-maxminddb', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-mbedtls', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-nss', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-openssl', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-vhostdb-pgsql', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-webdav', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-mod-wolfssl', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-modules-dbi', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-modules-ldap', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-modules-lua', 'pkgver': '1.4.65-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'lighttpd-modules-mysql', 'pkgver': '1.4.65-2ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lighttpd / lighttpd-dev / lighttpd-mod-authn-gssapi / etc');
}
