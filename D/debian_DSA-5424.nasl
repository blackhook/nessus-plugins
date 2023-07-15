#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5424. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177293);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_name(english:"Debian DSA-5424-1 : php7.4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5424
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.4");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5424");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/php7.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php7.4 packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/14");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libapache2-mod-php7.4', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'libphp7.4-embed', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-bcmath', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-bz2', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-cgi', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-cli', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-common', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-curl', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-dba', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-dev', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-enchant', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-fpm', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-gd', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-gmp', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-imap', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-interbase', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-intl', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-json', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-ldap', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-mbstring', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-mysql', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-odbc', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-opcache', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-pgsql', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-phpdbg', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-pspell', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-readline', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-snmp', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-soap', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-sqlite3', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-sybase', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-tidy', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-xml', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-xmlrpc', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-xsl', 'reference': '7.4.33-1+deb11u4'},
    {'release': '11.0', 'prefix': 'php7.4-zip', 'reference': '7.4.33-1+deb11u4'}
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
    severity   : SECURITY_HOLE,
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
