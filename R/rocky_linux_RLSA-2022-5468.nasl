##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:5468.
##

include('compat.inc');

if (description)
{
  script_id(162978);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/11");

  script_cve_id("CVE-2022-31626");
  script_xref(name:"RLSA", value:"2022:5468");

  script_name(english:"Rocky Linux 8 : php:8.0 (RLSA-2022:5468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:5468 advisory.

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension
    with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the
    connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote
    code execution vulnerability. (CVE-2022-31626)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:5468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2098523");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31626");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/11");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug3-debugsource");
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

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'apcu-panel-5.1.20-1.module+el8.6.0+790+fc63e43f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'apcu-panel-5.1'},
    {'reference':'libzip-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-1.7'},
    {'reference':'libzip-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-1.7'},
    {'reference':'libzip-debuginfo-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-debuginfo-1.7'},
    {'reference':'libzip-debuginfo-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-debuginfo-1.7'},
    {'reference':'libzip-debugsource-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-debugsource-1.7'},
    {'reference':'libzip-debugsource-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-debugsource-1.7'},
    {'reference':'libzip-devel-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-devel-1.7'},
    {'reference':'libzip-devel-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-devel-1.7'},
    {'reference':'libzip-tools-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-tools-1.7'},
    {'reference':'libzip-tools-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-tools-1.7'},
    {'reference':'libzip-tools-debuginfo-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-tools-debuginfo-1.7'},
    {'reference':'libzip-tools-debuginfo-1.7.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'libzip-tools-debuginfo-1.7'},
    {'reference':'php-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-8'},
    {'reference':'php-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-8'},
    {'reference':'php-bcmath-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-bcmath-8'},
    {'reference':'php-bcmath-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-bcmath-8'},
    {'reference':'php-bcmath-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-bcmath-debuginfo-8'},
    {'reference':'php-bcmath-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-bcmath-debuginfo-8'},
    {'reference':'php-cli-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-cli-8'},
    {'reference':'php-cli-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-cli-8'},
    {'reference':'php-cli-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-cli-debuginfo-8'},
    {'reference':'php-cli-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-cli-debuginfo-8'},
    {'reference':'php-common-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-common-8'},
    {'reference':'php-common-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-common-8'},
    {'reference':'php-common-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-common-debuginfo-8'},
    {'reference':'php-common-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-common-debuginfo-8'},
    {'reference':'php-dba-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dba-8'},
    {'reference':'php-dba-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dba-8'},
    {'reference':'php-dba-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dba-debuginfo-8'},
    {'reference':'php-dba-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dba-debuginfo-8'},
    {'reference':'php-dbg-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dbg-8'},
    {'reference':'php-dbg-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dbg-8'},
    {'reference':'php-dbg-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dbg-debuginfo-8'},
    {'reference':'php-dbg-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-dbg-debuginfo-8'},
    {'reference':'php-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-debuginfo-8'},
    {'reference':'php-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-debuginfo-8'},
    {'reference':'php-debugsource-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-debugsource-8'},
    {'reference':'php-debugsource-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-debugsource-8'},
    {'reference':'php-devel-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-devel-8'},
    {'reference':'php-devel-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-devel-8'},
    {'reference':'php-embedded-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-embedded-8'},
    {'reference':'php-embedded-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-embedded-8'},
    {'reference':'php-embedded-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-embedded-debuginfo-8'},
    {'reference':'php-embedded-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-embedded-debuginfo-8'},
    {'reference':'php-enchant-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-enchant-8'},
    {'reference':'php-enchant-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-enchant-8'},
    {'reference':'php-enchant-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-enchant-debuginfo-8'},
    {'reference':'php-enchant-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-enchant-debuginfo-8'},
    {'reference':'php-ffi-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ffi-8'},
    {'reference':'php-ffi-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ffi-8'},
    {'reference':'php-ffi-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ffi-debuginfo-8'},
    {'reference':'php-ffi-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ffi-debuginfo-8'},
    {'reference':'php-fpm-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-fpm-8'},
    {'reference':'php-fpm-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-fpm-8'},
    {'reference':'php-fpm-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-fpm-debuginfo-8'},
    {'reference':'php-fpm-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-fpm-debuginfo-8'},
    {'reference':'php-gd-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gd-8'},
    {'reference':'php-gd-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gd-8'},
    {'reference':'php-gd-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gd-debuginfo-8'},
    {'reference':'php-gd-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gd-debuginfo-8'},
    {'reference':'php-gmp-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gmp-8'},
    {'reference':'php-gmp-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gmp-8'},
    {'reference':'php-gmp-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gmp-debuginfo-8'},
    {'reference':'php-gmp-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-gmp-debuginfo-8'},
    {'reference':'php-intl-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-intl-8'},
    {'reference':'php-intl-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-intl-8'},
    {'reference':'php-intl-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-intl-debuginfo-8'},
    {'reference':'php-intl-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-intl-debuginfo-8'},
    {'reference':'php-ldap-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ldap-8'},
    {'reference':'php-ldap-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ldap-8'},
    {'reference':'php-ldap-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ldap-debuginfo-8'},
    {'reference':'php-ldap-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-ldap-debuginfo-8'},
    {'reference':'php-mbstring-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mbstring-8'},
    {'reference':'php-mbstring-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mbstring-8'},
    {'reference':'php-mbstring-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mbstring-debuginfo-8'},
    {'reference':'php-mbstring-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mbstring-debuginfo-8'},
    {'reference':'php-mysqlnd-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mysqlnd-8'},
    {'reference':'php-mysqlnd-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mysqlnd-8'},
    {'reference':'php-mysqlnd-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mysqlnd-debuginfo-8'},
    {'reference':'php-mysqlnd-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-mysqlnd-debuginfo-8'},
    {'reference':'php-odbc-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-odbc-8'},
    {'reference':'php-odbc-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-odbc-8'},
    {'reference':'php-odbc-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-odbc-debuginfo-8'},
    {'reference':'php-odbc-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-odbc-debuginfo-8'},
    {'reference':'php-opcache-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-opcache-8'},
    {'reference':'php-opcache-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-opcache-8'},
    {'reference':'php-opcache-debuginfo-7.4.19-3.module+el8.6.0+990+389ef54a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-opcache-debuginfo-7'},
    {'reference':'php-opcache-debuginfo-7.4.19-3.module+el8.6.0+990+389ef54a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-opcache-debuginfo-7'},
    {'reference':'php-opcache-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-opcache-debuginfo-8'},
    {'reference':'php-opcache-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-opcache-debuginfo-8'},
    {'reference':'php-pdo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pdo-8'},
    {'reference':'php-pdo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pdo-8'},
    {'reference':'php-pdo-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pdo-debuginfo-8'},
    {'reference':'php-pdo-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pdo-debuginfo-8'},
    {'reference':'php-pear-1.10.13-1.module+el8.6.0+790+fc63e43f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pear-1.10'},
    {'reference':'php-pecl-apcu-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-5.1'},
    {'reference':'php-pecl-apcu-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-5.1'},
    {'reference':'php-pecl-apcu-debuginfo-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-debuginfo-5.1'},
    {'reference':'php-pecl-apcu-debuginfo-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-debuginfo-5.1'},
    {'reference':'php-pecl-apcu-debugsource-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-debugsource-5.1'},
    {'reference':'php-pecl-apcu-debugsource-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-debugsource-5.1'},
    {'reference':'php-pecl-apcu-devel-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-devel-5.1'},
    {'reference':'php-pecl-apcu-devel-5.1.20-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-apcu-devel-5.1'},
    {'reference':'php-pecl-rrd-2.0.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-rrd-2.0'},
    {'reference':'php-pecl-rrd-2.0.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-rrd-2.0'},
    {'reference':'php-pecl-rrd-debuginfo-2.0.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-rrd-debuginfo-2.0'},
    {'reference':'php-pecl-rrd-debuginfo-2.0.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-rrd-debuginfo-2.0'},
    {'reference':'php-pecl-rrd-debugsource-2.0.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-rrd-debugsource-2.0'},
    {'reference':'php-pecl-rrd-debugsource-2.0.3-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-rrd-debugsource-2.0'},
    {'reference':'php-pecl-xdebug3-3.1.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug3-3.1.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug3-debuginfo-3.1.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug3-debuginfo-3.1.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug3-debugsource-3.1.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug3-debugsource-3.1.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-1.19.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-zip-1.19'},
    {'reference':'php-pecl-zip-1.19.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-zip-1.19'},
    {'reference':'php-pecl-zip-debuginfo-1.19.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-zip-debuginfo-1.19'},
    {'reference':'php-pecl-zip-debuginfo-1.19.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-zip-debuginfo-1.19'},
    {'reference':'php-pecl-zip-debugsource-1.19.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-zip-debugsource-1.19'},
    {'reference':'php-pecl-zip-debugsource-1.19.2-1.module+el8.6.0+790+fc63e43f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pecl-zip-debugsource-1.19'},
    {'reference':'php-pgsql-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pgsql-8'},
    {'reference':'php-pgsql-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pgsql-8'},
    {'reference':'php-pgsql-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pgsql-debuginfo-8'},
    {'reference':'php-pgsql-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-pgsql-debuginfo-8'},
    {'reference':'php-process-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-process-8'},
    {'reference':'php-process-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-process-8'},
    {'reference':'php-process-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-process-debuginfo-8'},
    {'reference':'php-process-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-process-debuginfo-8'},
    {'reference':'php-snmp-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-snmp-8'},
    {'reference':'php-snmp-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-snmp-8'},
    {'reference':'php-snmp-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-snmp-debuginfo-8'},
    {'reference':'php-snmp-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-snmp-debuginfo-8'},
    {'reference':'php-soap-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-soap-8'},
    {'reference':'php-soap-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-soap-8'},
    {'reference':'php-soap-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-soap-debuginfo-8'},
    {'reference':'php-soap-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-soap-debuginfo-8'},
    {'reference':'php-xml-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-xml-8'},
    {'reference':'php-xml-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-xml-8'},
    {'reference':'php-xml-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-xml-debuginfo-8'},
    {'reference':'php-xml-debuginfo-8.0.13-3.module+el8.6.0+989+3fbff15c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'php-xml-debuginfo-8'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
