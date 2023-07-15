#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1989.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157782);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-25215");
  script_xref(name:"RLSA", value:"2021:1989");
  script_xref(name:"IAVA", value:"2021-A-0206-S");

  script_name(english:"Rocky Linux 8 : bind (RLSA-2021:1989)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:1989 advisory.

  - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND
    9.17 development branch, when a vulnerable version of named receives a query for a record triggering the
    flaw described above, the named process will terminate due to a failed assertion check. The vulnerability
    affects all currently maintained BIND 9 branches (9.11, 9.11-S, 9.16, 9.16-S, 9.17) as well as all other
    versions of BIND 9. (CVE-2021-25215)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1953857");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-export-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-libs-lite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-pkcs11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-pkcs11-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-pkcs11-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-sdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
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
    {'reference':'bind-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-chroot-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-chroot-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-debuginfo-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-debugsource-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-debugsource-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-debugsource-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-devel-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-devel-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-devel-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-devel-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-devel-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-devel-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-libs-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-libs-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-libs-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-export-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-lite-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-lite-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-lite-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-lite-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-lite-debuginfo-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-lite-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-license-9.11.26-4.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-lite-devel-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-lite-devel-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-lite-devel-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-devel-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-devel-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-devel-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-libs-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-libs-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-libs-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-libs-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-utils-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-utils-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-utils-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-pkcs11-utils-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-sdb-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-sdb-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-sdb-chroot-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-sdb-chroot-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-sdb-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-sdb-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-utils-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-utils-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-utils-debuginfo-9.11.26-4.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-utils-debuginfo-9.11.26-4.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-bind-9.11.26-4.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-debuginfo / bind-debugsource / bind-devel / etc');
}
