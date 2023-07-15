#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0667-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158569);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-0920");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0667-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"SUSE SLES12 / SLES15 Security Update : kernel (Live Patch 21 for SLE 12 SP4) (SUSE-SU-2022:0667-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES15 host has packages installed that are affected by a vulnerability as referenced in
the SUSE-SU-2022:0667-1 advisory.

  - In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References:
    Upstream kernel (CVE-2021-0920)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194463");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010327.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?438f34c8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0920");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0920");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_69-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_72-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_75-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_78-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_77-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_141-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_144-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_147-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_150-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES15', 'SUSE (' + os_ver + ')');

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '4.12.14-150.69-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_69-default-15-2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.72-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_72-default-12-2.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.75-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_75-default-9-2.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.78-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_78-default-4-2.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-95.77-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_77-default-11-2.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.4.180-94.141-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_4_180-94_141-default-15-2.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
          {'reference':'kgraft-patch-4_4_180-94_141-default-15-2.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']}
        ]
      },
      '4.4.180-94.144-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_4_180-94_144-default-12-2.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
          {'reference':'kgraft-patch-4_4_180-94_144-default-12-2.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']}
        ]
      },
      '4.4.180-94.147-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_4_180-94_147-default-9-2.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
          {'reference':'kgraft-patch-4_4_180-94_147-default-9-2.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']}
        ]
      },
      '4.4.180-94.150-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_4_180-94_150-default-5-2.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
          {'reference':'kgraft-patch-4_4_180-94_150-default-5-2.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']}
        ]
      }
    }
  }
];

var ltss_caveat_required = FALSE;
var flag = 0;
var kernel_affected = FALSE;
foreach var kernel_array ( kernel_live_checks ) {
  var kpatch_details = kernel_array['kernels'][uname_r];
  if (empty_or_null(kpatch_details)) continue;
  kernel_affected = TRUE;
  foreach var package_array ( kpatch_details['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var exists_check = NULL;
    var rpm_spec_vers_cmp = NULL;
    if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
    if (!empty_or_null(package_array['release'])) _release = package_array['release'];
    if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
    if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
    if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
    if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
    if (reference && _release) {
      if (exists_check) {
        var check_flag = 0;
        foreach var check (exists_check) {
          if (!rpm_exists(release:_release, rpm:check)) continue;
          if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
          check_flag++;
        }
        if (!check_flag) continue;
      }
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

# No kpatch details found for the running kernel version
if (!kernel_affected) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-4_12_14-150_69-default / etc');
}
