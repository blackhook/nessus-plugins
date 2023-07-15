#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5006-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151583);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-7068",
    "CVE-2020-7071",
    "CVE-2021-21702",
    "CVE-2021-21704",
    "CVE-2021-21705"
  );
  script_xref(name:"USN", value:"5006-2");
  script_xref(name:"IAVA", value:"2020-A-0373-S");
  script_xref(name:"IAVA", value:"2021-A-0009-S");
  script_xref(name:"IAVA", value:"2021-A-0082-S");

  script_name(english:"Ubuntu 16.04 LTS : PHP vulnerabilities (USN-5006-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5006-2 advisory.

  - In PHP versions 7.2.x below 7.2.33, 7.3.x below 7.3.21 and 7.4.x below 7.4.9, while processing PHAR files
    using phar extension, phar_parse_zipfile could be tricked into accessing freed memory, which could lead to
    a crash or information disclosure. (CVE-2020-7068)

  - In PHP versions 7.3.x below 7.3.26, 7.4.x below 7.4.14 and 8.0.0, when validating URL with functions like
    filter_var($url, FILTER_VALIDATE_URL), PHP will accept an URL with invalid password as valid URL. This may
    lead to functions that rely on URL being valid to mis-parse the URL and produce wrong data as components
    of the URL. (CVE-2020-7071)

  - In PHP versions 7.3.x below 7.3.27, 7.4.x below 7.4.15 and 8.0.x below 8.0.2, when using SOAP extension to
    connect to a SOAP server, a malicious SOAP server could return malformed XML data as a response that would
    cause PHP to access a null pointer and thus cause a crash. (CVE-2021-21702)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5006-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp5-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.0-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-xsl");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libapache2-mod-php7.0', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'libphp7.0-embed', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-bcmath', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-bz2', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-cgi', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-cli', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-common', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-curl', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-dba', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-dev', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-enchant', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-fpm', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-gd', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-gmp', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-imap', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-interbase', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-intl', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-json', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-ldap', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-mbstring', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-mcrypt', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-mysql', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-odbc', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-opcache', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-pgsql', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-phpdbg', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-pspell', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-readline', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-recode', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-snmp', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-soap', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-sqlite3', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-sybase', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-tidy', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-xml', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-xmlrpc', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-xsl', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'},
    {'osver': '16.04', 'pkgname': 'php7.0-zip', 'pkgver': '7.0.33-0ubuntu0.16.04.16+esm1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.0 / libphp7.0-embed / php7.0 / php7.0-bcmath / etc');
}
