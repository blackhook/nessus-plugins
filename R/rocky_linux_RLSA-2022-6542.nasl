#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:6542.
##

include('compat.inc');

if (description)
{
  script_id(167791);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2020-28948", "CVE-2020-28949", "CVE-2020-36193");
  script_xref(name:"RLSA", value:"2022:6542");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"Rocky Linux 8 : php:7.4 (RLSA-2022:6542)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:6542 advisory.

  - Archive_Tar through 1.4.10 has :// filename sanitization only to address phar attacks, and thus any other
    stream-wrapper attack (such as file:// to overwrite files) can still succeed. (CVE-2020-28949)

  - Archive_Tar through 1.4.10 allows an unserialization attack because phar: is blocked but PHAR: is not
    blocked. (CVE-2020-28948)

  - Tar.php in Archive_Tar through 1.4.11 allows write operations with Directory Traversal due to inadequate
    checking of symbolic links, a related issue to CVE-2020-28948. (CVE-2020-36193)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:6542");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28949");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PEAR Archive_Tar 1.4.10 Arbitrary File Write');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dbg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-embedded-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mysqlnd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-rrd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-rrd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-process-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'apcu-panel-5.1.18-1.module+el8.6.0+789+2130c178', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-debuginfo-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-debuginfo-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-debugsource-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-debugsource-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-devel-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-devel-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-tools-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-tools-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-tools-debuginfo-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-tools-debuginfo-1.6.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debugsource-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-debugsource-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-json-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-json-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-json-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-json-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pear-1.10.13-1.module+el8.6.0+1006+0d5a469f', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'php-pecl-apcu-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-debuginfo-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-debuginfo-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-debugsource-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-debugsource-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-devel-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-devel-5.1.18-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-2.0.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-2.0.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-debuginfo-2.0.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-debuginfo-2.0.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-debugsource-2.0.1-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-debugsource-2.0.1-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-2.9.5-1.module+el8.4.0+415+e936cba3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-2.9.5-1.module+el8.4.0+415+e936cba3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-debuginfo-2.9.5-1.module+el8.4.0+415+e936cba3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-debuginfo-2.9.5-1.module+el8.4.0+415+e936cba3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-debugsource-2.9.5-1.module+el8.4.0+415+e936cba3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-debugsource-2.9.5-1.module+el8.4.0+415+e936cba3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-1.18.2-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-1.18.2-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-debuginfo-1.18.2-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-debuginfo-1.18.2-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-debugsource-1.18.2-1.module+el8.6.0+789+2130c178', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-debugsource-1.18.2-1.module+el8.6.0+789+2130c178', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xmlrpc-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xmlrpc-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xmlrpc-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xmlrpc-debuginfo-7.4.19-4.module+el8.6.0+1006+0d5a469f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-debuginfo / libzip-debugsource / etc');
}
