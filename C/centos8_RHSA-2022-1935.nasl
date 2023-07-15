##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2022:1935. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160907);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-21703", "CVE-2021-21705");
  script_xref(name:"RHSA", value:"2022:1935");
  script_xref(name:"IAVA", value:"2021-A-0503-S");

  script_name(english:"CentOS 8 : php:7.4 (CESA-2022:1935)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2022:1935 advisory.

  - php: Local privilege escalation via PHP-FPM (CVE-2021-21703)

  - php: SSRF bypass in FILTER_VALIDATE_URL (CVE-2021-21705)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1935");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'apcu-panel-5.1.18-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apcu-panel-5.1.18-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-1.6.1-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-1.6.1-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-devel-1.6.1-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-devel-1.6.1-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-tools-1.6.1-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libzip-tools-1.6.1-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-json-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-json-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pear-1.10.12-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pear-1.10.12-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-5.1.18-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-5.1.18-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-devel-5.1.18-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-apcu-devel-5.1.18-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-2.0.1-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-rrd-2.0.1-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-2.9.5-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-xdebug-2.9.5-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-1.18.2-1.module_el8.3.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pecl-zip-1.18.2-1.module_el8.3.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xmlrpc-7.4.19-2.module_el8.6.0', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xmlrpc-7.4.19-2.module_el8.6.0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-devel / libzip-tools / php / php-bcmath / etc');
}
