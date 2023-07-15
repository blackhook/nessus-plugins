#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5300-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158679);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2017-8923",
    "CVE-2017-9118",
    "CVE-2017-9120",
    "CVE-2021-21707"
  );
  script_xref(name:"USN", value:"5300-3");
  script_xref(name:"IAVB", value:"2017-B-0060-S");
  script_xref(name:"IAVA", value:"2021-A-0566");

  script_name(english:"Ubuntu 21.10 : PHP vulnerabilities (USN-5300-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 21.10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
USN-5300-3 advisory.

  - The zend_string_extend function in Zend/zend_string.h in PHP through 7.1.5 does not prevent changes to
    string objects that result in a negative length, which allows remote attackers to cause a denial of
    service (application crash) or possibly have unspecified other impact by leveraging a script's use of .=
    with a long string. (CVE-2017-8923)

  - PHP 7.1.5 has an Out of bounds access in php_pcre_replace_impl via a crafted preg_replace call.
    (CVE-2017-9118)

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
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5300-3");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libphp8.0-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php8.0-zip");
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
if (! ('21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '21.10', 'pkgname': 'libapache2-mod-php8.0', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'libphp8.0-embed', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-bcmath', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-bz2', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-cgi', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-cli', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-common', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-curl', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-dba', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-dev', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-enchant', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-fpm', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-gd', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-gmp', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-imap', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-interbase', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-intl', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-ldap', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-mbstring', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-mysql', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-odbc', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-opcache', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-pgsql', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-phpdbg', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-pspell', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-readline', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-snmp', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-soap', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-sqlite3', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-sybase', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-tidy', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-xml', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-xsl', 'pkgver': '8.0.8-1ubuntu0.3'},
    {'osver': '21.10', 'pkgname': 'php8.0-zip', 'pkgver': '8.0.8-1ubuntu0.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php8.0 / libphp8.0-embed / php8.0 / php8.0-bcmath / etc');
}
