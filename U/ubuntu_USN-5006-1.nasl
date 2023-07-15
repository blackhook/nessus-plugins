#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5006-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151444);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-7068",
    "CVE-2020-7071",
    "CVE-2021-21702",
    "CVE-2021-21704",
    "CVE-2021-21705"
  );
  script_xref(name:"USN", value:"5006-1");
  script_xref(name:"IAVA", value:"2020-A-0373-S");
  script_xref(name:"IAVA", value:"2021-A-0009-S");
  script_xref(name:"IAVA", value:"2021-A-0082-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : PHP vulnerabilities (USN-5006-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5006-1 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5006-1");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
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
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'libapache2-mod-php7.2', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'libphp7.2-embed', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-bcmath', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-bz2', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-cgi', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-cli', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-common', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-curl', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-dba', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-dev', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-enchant', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-fpm', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-gd', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-gmp', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-imap', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-interbase', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-intl', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-json', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-ldap', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-mbstring', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-mysql', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-odbc', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-opcache', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-pgsql', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-phpdbg', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-pspell', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-readline', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-recode', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-snmp', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-soap', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-sqlite3', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-sybase', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-tidy', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-xml', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-xmlrpc', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-xsl', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '18.04', 'pkgname': 'php7.2-zip', 'pkgver': '7.2.24-0ubuntu0.18.04.8'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'libphp7.4-embed', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-bcmath', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-bz2', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-cgi', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-cli', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-common', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-curl', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-dba', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-dev', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-enchant', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-fpm', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-gd', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-gmp', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-imap', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-interbase', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-intl', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-json', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-ldap', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-mbstring', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-mysql', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-odbc', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-opcache', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-pgsql', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-phpdbg', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-pspell', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-readline', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-snmp', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-soap', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-sqlite3', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-sybase', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-tidy', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-xml', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-xmlrpc', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-xsl', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.04', 'pkgname': 'php7.4-zip', 'pkgver': '7.4.3-4ubuntu2.5'},
    {'osver': '20.10', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'libphp7.4-embed', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-bcmath', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-bz2', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-cgi', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-cli', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-common', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-curl', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-dba', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-dev', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-enchant', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-fpm', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-gd', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-gmp', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-imap', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-interbase', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-intl', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-json', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-ldap', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-mbstring', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-mysql', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-odbc', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-opcache', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-pgsql', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-phpdbg', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-pspell', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-readline', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-snmp', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-soap', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-sqlite3', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-sybase', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-tidy', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-xml', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-xmlrpc', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-xsl', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'php7.4-zip', 'pkgver': '7.4.9-1ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'libapache2-mod-php7.4', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'libphp7.4-embed', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-bcmath', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-bz2', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-cgi', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-cli', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-common', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-curl', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-dba', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-dev', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-enchant', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-fpm', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-gd', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-gmp', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-imap', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-interbase', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-intl', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-json', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-ldap', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-mbstring', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-mysql', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-odbc', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-opcache', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-pgsql', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-phpdbg', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-pspell', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-readline', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-snmp', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-soap', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-sqlite3', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-sybase', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-tidy', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-xml', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-xmlrpc', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-xsl', 'pkgver': '7.4.16-1ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'php7.4-zip', 'pkgver': '7.4.16-1ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.2 / libapache2-mod-php7.4 / libphp7.2-embed / etc');
}
