#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5425. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177294);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_name(english:"Debian DSA-5425-1 : php8.2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5425
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php8.2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5425");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/php8.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php8.2 packages.

For the stable distribution (bookworm), this problem has been fixed in version 8.2.7-1~deb12u1.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp8.2-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php8.2-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'libapache2-mod-php8.2', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libphp8.2-embed', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-bcmath', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-bz2', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-cgi', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-cli', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-common', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-curl', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-dba', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-dev', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-enchant', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-fpm', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-gd', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-gmp', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-imap', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-interbase', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-intl', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-ldap', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-mbstring', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-mysql', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-odbc', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-opcache', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-pgsql', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-phpdbg', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-pspell', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-readline', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-snmp', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-soap', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-sqlite3', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-sybase', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-tidy', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-xml', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-xsl', 'reference': '8.2.7-1~deb12u1'},
    {'release': '12.0', 'prefix': 'php8.2-zip', 'reference': '8.2.7-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php8.2 / libphp8.2-embed / php8.2 / php8.2-bcmath / etc');
}
