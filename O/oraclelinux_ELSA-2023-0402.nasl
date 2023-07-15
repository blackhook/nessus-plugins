#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-0402.
##

include('compat.inc');

if (description)
{
  script_id(170515);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_cve_id("CVE-2021-25220", "CVE-2022-2795");
  script_xref(name:"IAVA", value:"2022-A-0387-S");
  script_xref(name:"IAVA", value:"2022-A-0122-S");

  script_name(english:"Oracle Linux 7 : bind (ELSA-2023-0402)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-0402 advisory.

  - By flooding the target resolver with queries exploiting this flaw an attacker can significantly impair the
    resolver's performance, effectively denying legitimate clients access to the DNS resolution service.
    (CVE-2022-2795)

  - BIND 9.11.0 -> 9.11.36 9.12.0 -> 9.16.26 9.17.0 -> 9.18.0 BIND Supported Preview Editions: 9.11.4-S1 ->
    9.11.36-S1 9.16.8-S1 -> 9.16.26-S1 Versions of BIND 9 earlier than those shown - back to 9.1.0, including
    Supported Preview Editions - are also believed to be affected but have not been tested as they are EOL.
    The cache could become poisoned with incorrect records leading to queries being made to the wrong servers,
    which might also result in false information being returned to clients. (CVE-2021-25220)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-0402.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'bind-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-chroot-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-chroot-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-devel-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-devel-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-devel-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-export-devel-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-export-devel-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-export-devel-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-export-libs-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-export-libs-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-export-libs-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-license-9.11.4-26.P2.el7_9.13', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.el7_9.13', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-utils-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-pkcs11-utils-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-sdb-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-sdb-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-sdb-chroot-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-sdb-chroot-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-utils-9.11.4-26.P2.el7_9.13', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-utils-9.11.4-26.P2.el7_9.13', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / etc');
}
