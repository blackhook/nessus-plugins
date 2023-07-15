##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5530-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163436);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-31627");
  script_xref(name:"USN", value:"5530-1");

  script_name(english:"Ubuntu 22.04 LTS : PHP vulnerability (USN-5530-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5530-1 advisory.

  - In PHP versions 8.1.x below 8.1.8, when fileinfo functions, such as finfo_buffer, due to incorrect patch
    applied to the third party code from libmagic, incorrect function may be used to free allocated memory,
    which may lead to heap corruption. (CVE-2022-31627)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5530-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp8.1-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.1-zip");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libapache2-mod-php8.0', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libapache2-mod-php8.1', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libphp8.1-embed', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-bcmath', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-bz2', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-cgi', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-cli', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-common', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-curl', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-dba', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-dev', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-enchant', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-fpm', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-gd', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-gmp', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-imap', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-interbase', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-intl', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-ldap', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-mbstring', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-mysql', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-odbc', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-opcache', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-pgsql', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-phpdbg', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-pspell', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-readline', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-snmp', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-soap', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-sqlite3', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-sybase', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-tidy', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-xml', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-xsl', 'pkgver': '8.1.2-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'php8.1-zip', 'pkgver': '8.1.2-1ubuntu2.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.4 / libapache2-mod-php8.0 / etc');
}
