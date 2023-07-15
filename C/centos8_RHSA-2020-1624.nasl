##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:1624. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145814);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2018-20783",
    "CVE-2019-9020",
    "CVE-2019-9021",
    "CVE-2019-9022",
    "CVE-2019-9023",
    "CVE-2019-9024",
    "CVE-2019-9637",
    "CVE-2019-9638",
    "CVE-2019-9639",
    "CVE-2019-9640",
    "CVE-2019-11034",
    "CVE-2019-11035",
    "CVE-2019-11036",
    "CVE-2019-11039",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042"
  );
  script_bugtraq_id(
    107121,
    107154,
    107156,
    107379,
    107794,
    108177,
    108520,
    108525
  );
  script_xref(name:"RHSA", value:"2020:1624");

  script_name(english:"CentOS 8 : php:7.2 (CESA-2020:1624)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:1624 advisory.

  - php: Buffer over-read in PHAR reading functions (CVE-2018-20783)

  - php: Heap buffer overflow in function exif_process_IFD_TAG() (CVE-2019-11034)

  - php: Heap buffer overflow in function exif_iif_add_value() (CVE-2019-11035)

  - php: Buffer over-read in exif_process_IFD_TAG() leading to information disclosure (CVE-2019-11036)

  - php: Out-of-bounds read due to integer overflow in iconv_mime_decode_headers() (CVE-2019-11039)

  - php: Buffer over-read in exif_read_data() (CVE-2019-11040)

  - php: Heap buffer over-read in exif_scan_thumbnail() (CVE-2019-11041)

  - php: Heap buffer over-read in exif_process_user_comment() (CVE-2019-11042)

  - php: Invalid memory access in function xmlrpc_decode() (CVE-2019-9020)

  - php: Heap-based buffer over-read in PHAR reading functions (CVE-2019-9021)

  - php: memcpy with negative length via crafted DNS response (CVE-2019-9022)

  - php: Heap-based buffer over-read in mbstring regular expression functions (CVE-2019-9023)

  - php: Out-of-bounds read in base64_decode_xmlrpc in ext/xmlrpc/libxmlrpc/base64.c (CVE-2019-9024)

  - php: File rename across filesystems may allow unwanted access during processing (CVE-2019-9637)

  - php: Uninitialized read in exif_process_IFD_in_MAKERNOTE (CVE-2019-9638, CVE-2019-9639)

  - php: Invalid read in exif_process_SOFn() (CVE-2019-9640)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1624");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9023");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.2');
if ('7.2' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:7.2': [
      {'reference':'apcu-panel-5.1.12-2.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apcu-panel-5.1.12-2.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.5.1-2.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.5.1-2.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.5.1-2.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.5.1-2.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.5.1-2.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.5.1-2.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.5-9.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.5-9.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.12-2.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.12-2.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.12-2.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.12-2.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.15.3-1.module_el8.1.0+209+03b9a8ff', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.15.3-1.module_el8.1.0+209+03b9a8ff', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.2.24-1.module_el8.2.0+313+b04d0a66', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
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
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.2');

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
