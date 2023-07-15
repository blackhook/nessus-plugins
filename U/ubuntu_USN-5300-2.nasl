#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5300-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158572);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2017-8923",
    "CVE-2017-9118",
    "CVE-2017-9119",
    "CVE-2017-9120",
    "CVE-2021-21707"
  );
  script_xref(name:"USN", value:"5300-2");
  script_xref(name:"IAVB", value:"2017-B-0060-S");
  script_xref(name:"IAVA", value:"2021-A-0566");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : PHP vulnerabilities (USN-5300-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5300-2 advisory.

  - The zend_string_extend function in Zend/zend_string.h in PHP through 7.1.5 does not prevent changes to
    string objects that result in a negative length, which allows remote attackers to cause a denial of
    service (application crash) or possibly have unspecified other impact by leveraging a script's use of .=
    with a long string. (CVE-2017-8923)

  - PHP 7.1.5 has an Out of bounds access in php_pcre_replace_impl via a crafted preg_replace call.
    (CVE-2017-9118)

  - The i_zval_ptr_dtor function in Zend/zend_variables.h in PHP 7.1.5 allows attackers to cause a denial of
    service (memory consumption and application crash) or possibly have unspecified other impact by triggering
    crafted operations on array data structures. (CVE-2017-9119)

  - PHP 7.x through 7.1.5 allows remote attackers to cause a denial of service (buffer overflow and
    application crash) or possibly have unspecified other impact via a long string because of an Integer
    overflow in mysqli_real_escape_string. (CVE-2017-9120)

  - In PHP versions 7.3.x below 7.3.33, 7.4.x below 7.4.26 and 8.0.x below 8.0.13, certain XML parsing
    functions, like simplexml_load_file(), URL-decode the filename passed to them. If that filename contains
    URL-encoded NUL character, this may cause the function to interpret this as the end of the filename, thus
    interpreting the filename differently from what the user intended, which may lead it to reading a
    different file than intended. (CVE-2021-21707)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5300-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9120");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.2-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp7.4-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.2-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php7.4-zip");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libapache2-mod-php7.2', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libphp7.2-embed', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-bcmath', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-bz2', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-cgi', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-cli', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-common', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-curl', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-dba', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-dev', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-enchant', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-fpm', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-gd', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-gmp', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-imap', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-interbase', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-intl', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-json', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-ldap', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-mbstring', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-mysql', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-odbc', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-opcache', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-pgsql', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-phpdbg', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-pspell', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-readline', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-recode', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-snmp', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-soap', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-sqlite3', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-sybase', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-tidy', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-xml', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-xmlrpc', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-xsl', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'php7.2-zip', 'pkgver': '7.2.24-0ubuntu0.18.04.11'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'libphp7.4-embed', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-bcmath', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-bz2', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-cgi', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-cli', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-common', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-curl', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-dba', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-dev', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-enchant', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-fpm', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-gd', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-gmp', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-imap', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-interbase', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-intl', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-json', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-ldap', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-mbstring', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-mysql', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-odbc', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-opcache', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-pgsql', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-phpdbg', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-pspell', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-readline', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-snmp', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-soap', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-sqlite3', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-sybase', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-tidy', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-xml', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-xmlrpc', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-xsl', 'pkgver': '7.4.3-4ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'php7.4-zip', 'pkgver': '7.4.3-4ubuntu2.10'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.2 / libapache2-mod-php7.4 / libphp7.2-embed / etc');
}
