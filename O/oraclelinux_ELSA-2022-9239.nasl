#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9239.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159117);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/21");

  script_cve_id("CVE-2022-24407");

  script_name(english:"Oracle Linux 6 : cyrus-sasl (ELSA-2022-9239)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-9239 advisory.

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9239.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cyrus-sasl-sql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'cyrus-sasl-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-2.1.23-15.0.1.el6_6.2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-2.1.23-15.0.1.el6_6.2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-sasl / cyrus-sasl-devel / cyrus-sasl-gssapi / etc');
}
