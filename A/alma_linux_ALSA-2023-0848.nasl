#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:0848.
##

include('compat.inc');

if (description)
{
  script_id(171735);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/21");

  script_cve_id(
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31630",
    "CVE-2022-31631",
    "CVE-2022-37454"
  );
  script_xref(name:"ALSA", value:"2023:0848");
  script_xref(name:"IAVA", value:"2022-A-0515-S");
  script_xref(name:"IAVA", value:"2022-A-0397");
  script_xref(name:"IAVA", value:"2022-A-0455-S");
  script_xref(name:"IAVA", value:"2023-A-0016-S");

  script_name(english:"AlmaLinux 8 : php:8.0 (ALSA-2023:0848)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:0848 advisory.

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the phar uncompressor code would recursively uncompress
    quines gzip files, resulting in an infinite loop. (CVE-2022-31628)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the vulnerability enables network and same-site
    attackers to set a standard insecure cookie in the victim's browser which is treated as a `__Host-` or
    `__Secure-` cookie by PHP applications. (CVE-2022-31629)

  - In PHP versions prior to 7.4.33, 8.0.25 and 8.2.12, when using imageloadfont() function in gd extension,
    it is possible to supply a specially crafted font file, such as if the loaded font is used with
    imagechar() function, the read outside allocated buffer will be used. This can lead to crashes or
    disclosure of confidential information. (CVE-2022-31630)

  - The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer
    overflow that allows attackers to execute arbitrary code or eliminate expected cryptographic properties.
    This occurs in the sponge function interface. (CVE-2022-37454)

  - php: PDO::quote() may return unquoted string due to an integer overflow (CVE-2022-31631)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-0848.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 190, 20, 674, 680);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-xdebug3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:8.0': [
      {'reference':'apcu-panel-5.1.20-1.module_el8.6.0+2739+efabdb8f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.7.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.7.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.7.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.7.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.7.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.7.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ffi-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.13-1.module_el8.6.0+3268+b150a051', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'php-pecl-apcu-5.1.20-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.20-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.20-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.20-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.3-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug3-3.1.2-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug3-3.1.2-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.19.2-1.module_el8.6.0+2739+efabdb8f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.19.2-1.module_el8.6.0+2739+efabdb8f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-8.0.27-1.module_el8.7.0+3401+dfb61c00', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
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
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.0');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
