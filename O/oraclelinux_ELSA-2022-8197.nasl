#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-8197.
##

include('compat.inc');

if (description)
{
  script_id(168077);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id("CVE-2021-21708", "CVE-2022-31625");

  script_name(english:"Oracle Linux 9 : php (ELSA-2022-8197)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-8197 advisory.

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when using Postgres
    database extension, supplying invalid parameters to the parametrized query may lead to PHP attempting to
    free memory using uninitialized data as pointers. This could lead to RCE vulnerability or denial of
    service. (CVE-2022-31625)

  - In PHP versions 7.4.x below 7.4.28, 8.0.x below 8.0.16, and 8.1.x below 8.1.3, when using filter functions
    with FILTER_VALIDATE_FLOAT filter and min/max limits, if the filter fails, there is a possibility to
    trigger use of allocated memory after free, which can result it crashes, and potentially in overwrite of
    other memory chunks and RCE. This issue affects: code that uses FILTER_VALIDATE_FLOAT with min/max limits.
    (CVE-2021-21708)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-8197.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31625");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'php-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-bcmath-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-cli-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-common-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dba-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-dbg-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-devel-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-embedded-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-enchant-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ffi-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-fpm-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gd-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-gmp-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-intl-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-ldap-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mbstring-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-mysqlnd-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-odbc-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-opcache-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pdo-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-pgsql-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-process-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-snmp-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-soap-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-8.0.20-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php-xml-8.0.20-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php / php-bcmath / php-cli / etc');
}
