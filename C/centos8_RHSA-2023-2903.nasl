#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:2903. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175912);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id(
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31630",
    "CVE-2022-31631",
    "CVE-2022-37454"
  );
  script_xref(name:"RHSA", value:"2023:2903");

  script_name(english:"CentOS 8 : php:7.4 (CESA-2023:2903)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2023:2903 advisory.

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the phar uncompressor code would recursively uncompress
    quines gzip files, resulting in an infinite loop. (CVE-2022-31628)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the vulnerability enables network and same-site
    attackers to set a standard insecure cookie in the victim's browser which is treated as a `__Host-` or
    `__Secure-` cookie by PHP applications. (CVE-2022-31629)

  - In PHP versions prior to 7.4.33, 8.0.25 and 8.2.12, when using imageloadfont() function in gd extension,
    it is possible to supply a specially crafted font file, such as if the loaded font is used with
    imagechar() function, the read outside allocated buffer will be used. This can lead to crashes or
    disclosure of confidential information. (CVE-2022-31630)

  - php: PDO::quote() may return unquoted string due to an integer overflow (CVE-2022-31631)

  - The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer
    overflow that allows attackers to execute arbitrary code or eliminate expected cryptographic properties.
    This occurs in the sponge function interface. (CVE-2022-37454)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:2903");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pecl-zip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.4');
if ('7.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:7.4': [
      {'reference':'apcu-panel-5.1.18-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apcu-panel-5.1.18-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.6.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.6.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.6.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.6.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.6.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.6.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.13-1.module_el8.7.0+1143+7b05a50f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.13-1.module_el8.7.0+1143+7b05a50f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.18-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.18-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.18-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.18-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.1-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug-2.9.5-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug-2.9.5-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.18.2-1.module_el8.3.0+396+9a0d79d6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.18.2-1.module_el8.3.0+396+9a0d79d6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.4');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-devel / libzip-tools / php-pear / etc');
}
