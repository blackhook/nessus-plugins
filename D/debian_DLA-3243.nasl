#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3243. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168859);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2021-21707",
    "CVE-2022-31625",
    "CVE-2022-31626",
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-37454"
  );
  script_xref(name:"IAVA", value:"2022-A-0515-S");

  script_name(english:"Debian DLA-3243-1 : php7.3 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3243 advisory.

  - In PHP versions 7.3.x below 7.3.33, 7.4.x below 7.4.26 and 8.0.x below 8.0.13, certain XML parsing
    functions, like simplexml_load_file(), URL-decode the filename passed to them. If that filename contains
    URL-encoded NUL character, this may cause the function to interpret this as the end of the filename, thus
    interpreting the filename differently from what the user intended, which may lead it to reading a
    different file than intended. (CVE-2021-21707)

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when using Postgres
    database extension, supplying invalid parameters to the parametrized query may lead to PHP attempting to
    free memory using uninitialized data as pointers. This could lead to RCE vulnerability or denial of
    service. (CVE-2022-31625)

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension
    with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the
    connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote
    code execution vulnerability. (CVE-2022-31626)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the phar uncompressor code would recursively uncompress
    quines gzip files, resulting in an infinite loop. (CVE-2022-31628)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the vulnerability enables network and same-site
    attackers to set a standard insecure cookie in the victim's browser which is treated as a `__Host-` or
    `__Secure-` cookie by PHP applications. (CVE-2022-31629)

  - The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer
    overflow that allows attackers to execute arbitrary code or eliminate expected cryptographic properties.
    This occurs in the sponge function interface. (CVE-2022-37454)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.3");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31628");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31629");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37454");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/php7.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php7.3 packages.

For Debian 10 buster, these problems have been fixed in version 7.3.31-1~deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31625");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php7.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp7.3-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libapache2-mod-php7.3', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'libphp7.3-embed', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-bcmath', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-bz2', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-cgi', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-cli', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-common', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-curl', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-dba', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-dev', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-enchant', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-fpm', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-gd', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-gmp', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-imap', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-interbase', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-intl', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-json', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-ldap', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-mbstring', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-mysql', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-odbc', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-opcache', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-pgsql', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-phpdbg', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-pspell', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-readline', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-recode', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-snmp', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-soap', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-sqlite3', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-sybase', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-tidy', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-xml', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-xmlrpc', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-xsl', 'reference': '7.3.31-1~deb10u2'},
    {'release': '10.0', 'prefix': 'php7.3-zip', 'reference': '7.3.31-1~deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.3 / libphp7.3-embed / php7.3 / php7.3-bcmath / etc');
}
