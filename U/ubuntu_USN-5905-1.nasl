#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5905-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172053);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31631",
    "CVE-2023-0568",
    "CVE-2023-0662"
  );
  script_xref(name:"USN", value:"5905-1");
  script_xref(name:"IAVA", value:"2023-A-0105-S");

  script_name(english:"Ubuntu 16.04 ESM : PHP vulnerabilities (USN-5905-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5905-1 advisory.

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the phar uncompressor code would recursively uncompress
    quines gzip files, resulting in an infinite loop. (CVE-2022-31628)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the vulnerability enables network and same-site
    attackers to set a standard insecure cookie in the victim's browser which is treated as a `__Host-` or
    `__Secure-` cookie by PHP applications. (CVE-2022-31629)

  - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, core path resolution function
    allocate buffer one byte too small. When resolving paths with lengths close to system MAXPATHLEN setting,
    this may lead to the byte after the allocated buffer being overwritten with NUL value, which might lead to
    unauthorized data access or modification. (CVE-2023-0568)

  - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, excessive number of parts in HTTP
    form upload can cause high resource consumption and excessive number of log entries. This can cause denial
    of service on the affected server by exhausting CPU resources or disk space. (CVE-2023-0662)

  - php: PDO::quote() may return unquoted string due to an integer overflow (CVE-2022-31631)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5905-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.0-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.0-zip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(16\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libapache2-mod-php7.0', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'libphp7.0-embed', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-bcmath', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-bz2', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-cgi', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-cli', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-common', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-curl', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-dba', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-dev', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-enchant', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-fpm', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-gd', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-gmp', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-imap', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-interbase', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-intl', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-json', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-ldap', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-mbstring', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-mcrypt', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-mysql', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-odbc', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-opcache', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-pgsql', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-phpdbg', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-pspell', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-readline', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-recode', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-snmp', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-soap', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-sqlite3', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-sybase', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-tidy', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-xml', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-xmlrpc', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-xsl', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'},
    {'osver': '16.04', 'pkgname': 'php7.0-zip', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.0 / libphp7.0-embed / php7.0 / php7.0-bcmath / etc');
}
