#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2794. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154514);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-21703");
  script_xref(name:"IAVA", value:"2021-A-0503-S");

  script_name(english:"Debian DLA-2794-1 : php7.0 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2794
advisory.

  - In PHP versions 7.3.x up to and including 7.3.31, 7.4.x below 7.4.25 and 8.0.x below 8.0.12, when running
    PHP FPM SAPI with main FPM daemon process running as root and child worker processes running as lower-
    privileged users, it is possible for the child processes to access memory shared with the main process and
    write to it, modifying it in a way that would cause the root process to conduct invalid memory reads and
    writes, which can be used to escalate privileges from local unprivileged user to the root user.
    (CVE-2021-21703)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=997003");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.0");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2794");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21703");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/php7.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php7.0 packages.

For Debian 9 stretch, this problem has been fixed in version 7.0.33-0+deb9u12.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp7.0-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'libapache2-mod-php7.0', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'libphp7.0-embed', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-bcmath', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-bz2', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-cgi', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-cli', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-common', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-curl', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-dba', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-dev', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-enchant', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-fpm', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-gd', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-gmp', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-imap', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-interbase', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-intl', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-json', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-ldap', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-mbstring', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-mcrypt', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-mysql', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-odbc', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-opcache', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-pgsql', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-phpdbg', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-pspell', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-readline', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-recode', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-snmp', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-soap', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-sqlite3', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-sybase', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-tidy', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-xml', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-xmlrpc', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-xsl', 'reference': '7.0.33-0+deb9u12'},
    {'release': '9.0', 'prefix': 'php7.0-zip', 'reference': '7.0.33-0+deb9u12'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.0 / libphp7.0-embed / php7.0 / php7.0-bcmath / etc');
}
