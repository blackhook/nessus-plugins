#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2708. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151676);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/10");

  script_cve_id(
    "CVE-2019-18218",
    "CVE-2020-7071",
    "CVE-2021-21702",
    "CVE-2021-21704",
    "CVE-2021-21705"
  );
  script_xref(name:"IAVA", value:"2021-A-0009-S");
  script_xref(name:"IAVA", value:"2021-A-0082-S");

  script_name(english:"Debian DLA-2708-1 : php7.0 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2708 advisory.

  - cdf_read_property_info in cdf.c in file through 5.37 does not restrict the number of CDF_VECTOR elements,
    which allows a heap-based buffer overflow (4-byte out-of-bounds write). (CVE-2019-18218)

  - In PHP versions 7.3.x below 7.3.26, 7.4.x below 7.4.14 and 8.0.0, when validating URL with functions like
    filter_var($url, FILTER_VALIDATE_URL), PHP will accept an URL with invalid password as valid URL. This may
    lead to functions that rely on URL being valid to mis-parse the URL and produce wrong data as components
    of the URL. (CVE-2020-7071)

  - In PHP versions 7.3.x below 7.3.27, 7.4.x below 7.4.15 and 8.0.x below 8.0.2, when using SOAP extension to
    connect to a SOAP server, a malicious SOAP server could return malformed XML data as a response that would
    cause PHP to access a null pointer and thus cause a crash. (CVE-2021-21702)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=942830");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.0");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2708");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-7071");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21702");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21705");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/php7.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php7.0 packages.

For Debian 9 stretch, these problems have been fixed in version 7.0.33-0+deb9u11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

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

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'libapache2-mod-php7.0', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'libphp7.0-embed', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-bcmath', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-bz2', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-cgi', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-cli', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-common', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-curl', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-dba', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-dev', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-enchant', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-fpm', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-gd', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-gmp', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-imap', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-interbase', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-intl', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-json', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-ldap', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-mbstring', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-mcrypt', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-mysql', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-odbc', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-opcache', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-pgsql', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-phpdbg', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-pspell', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-readline', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-recode', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-snmp', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-soap', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-sqlite3', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-sybase', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-tidy', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-xml', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-xmlrpc', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-xsl', 'reference': '7.0.33-0+deb9u11'},
    {'release': '9.0', 'prefix': 'php7.0-zip', 'reference': '7.0.33-0+deb9u11'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
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
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-php7.0 / libphp7.0-embed / php7.0 / php7.0-bcmath / etc');
}
