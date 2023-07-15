#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-7628.
##

include('compat.inc');

if (description)
{
  script_id(167528);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id("CVE-2021-21707", "CVE-2021-21708", "CVE-2021-32610");
  script_xref(name:"IAVA", value:"2021-A-0566");

  script_name(english:"Oracle Linux 8 : php:7.4 (ELSA-2022-7628)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-7628 advisory.

  - In PHP versions 7.4.x below 7.4.28, 8.0.x below 8.0.16, and 8.1.x below 8.1.3, when using filter functions
    with FILTER_VALIDATE_FLOAT filter and min/max limits, if the filter fails, there is a possibility to
    trigger use of allocated memory after free, which can result it crashes, and potentially in overwrite of
    other memory chunks and RCE. This issue affects: code that uses FILTER_VALIDATE_FLOAT with min/max limits.
    (CVE-2021-21708)

  - In PHP versions 7.3.x below 7.3.33, 7.4.x below 7.4.26 and 8.0.x below 8.0.13, certain XML parsing
    functions, like simplexml_load_file(), URL-decode the filename passed to them. If that filename contains
    URL-encoded NUL character, this may cause the function to interpret this as the end of the filename, thus
    interpreting the filename differently from what the user intended, which may lead it to reading a
    different file than intended. (CVE-2021-21707)

  - In Archive_Tar before 1.4.14, symlinks can refer to targets outside of the extracted archive, a different
    vulnerability than CVE-2020-36193. (CVE-2021-32610)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-7628.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.4');
if ('7.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:7.4': [
      {'reference':'apcu-panel-5.1.18-1.module+el8.3.0+7685+72d70b58', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.6.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.6.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.6.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.6.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.6.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.6.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.13-1.module+el8.7.0+20800+8e29b882', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'php-pecl-apcu-5.1.18-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.18-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.18-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.18-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.1-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug-2.9.5-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug-2.9.5-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.18.2-1.module+el8.3.0+7685+72d70b58', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.18.2-1.module+el8.3.0+7685+72d70b58', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.4.30-1.module+el8.7.0+20800+8e29b882', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.4');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-devel / etc');
}
