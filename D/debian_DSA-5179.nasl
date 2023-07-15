#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5179. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162983);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-31625", "CVE-2022-31626");

  script_name(english:"Debian DSA-5179-1 : php7.4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5179 advisory.

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when using Postgres
    database extension, supplying invalid parameters to the parametrized query may lead to PHP attempting to
    free memory using uninitialized data as pointers. This could lead to RCE vulnerability or denial of
    service. (CVE-2022-31625)

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension
    with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the
    connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote
    code execution vulnerability. (CVE-2022-31626)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.4");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5179");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31626");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/php7.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php7.4 packages.

For the stable distribution (bullseye), these problems have been fixed in version 7.4.30-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31625");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31626");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp7.4-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.4-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libapache2-mod-php7.4', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libphp7.4-embed', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-bcmath', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-bz2', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-cgi', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-cli', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-common', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-curl', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-dba', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-dev', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-enchant', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-fpm', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-gd', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-gmp', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-imap', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-interbase', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-intl', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-json', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-ldap', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-mbstring', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-mysql', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-odbc', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-opcache', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-pgsql', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-phpdbg', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-pspell', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-readline', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-snmp', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-soap', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-sqlite3', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-sybase', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-tidy', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-xml', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-xmlrpc', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-xsl', 'reference': '7.4.30-1+deb11u1'},
    {'release': '11.0', 'prefix': 'php7.4-zip', 'reference': '7.4.30-1+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.4 / libphp7.4-embed / php7.4 / php7.4-bcmath / etc');
}
