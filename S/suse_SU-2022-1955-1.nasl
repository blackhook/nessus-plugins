##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1955-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(161916);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2022-1048", "CVE-2022-30594");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1955-1");

  script_name(english:"SUSE SLES12 / SLES15 Security Update : kernel (Live Patch 1 for SLE 15 SP3) (SUSE-SU-2022:1955-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:1955-1 advisory.

  - A use-after-free flaw was found in the Linux kernel's sound subsystem in the way a user triggers
    concurrent calls of PCM hw_params. The hw_free ioctls or similar race condition happens inside ALSA PCM
    for other ioctls. This flaw allows a local user to crash or potentially escalate their privileges on the
    system. (CVE-2022-1048)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199834");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-June/011243.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2349ddf0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30594");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1048");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30594");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_75-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_78-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_86-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-197_108-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-197_99-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_53_4-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_67-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_70-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_75-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_78-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_86-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_93-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_96-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_16-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_19-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_24-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_27-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_34-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_37-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_40-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_5-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_106-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_110-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_113-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_74-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_77-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_80-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_91-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_77-default");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '4.12.14-122.106-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_106-default-8-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.110-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_110-default-6-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.113-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_113-default-5-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.74-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_74-default-16-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.77-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_77-default-16-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.80-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_80-default-15-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.83-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_83-default-14-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.88-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_88-default-12-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.91-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_91-default-12-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-150.75-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_75-default-14-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.78-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_78-default-9-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.83-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_83-default-5-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.86-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_86-default-4-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-197.108-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-197_108-default-4-150100.2.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-197.99-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-197_99-default-14-150100.2.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-95.77-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_77-default-16-2.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '5.3.18-24.53.4-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_53_4-default-16-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.67-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_67-default-16-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.70-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_70-default-16-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.75-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_75-default-15-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.78-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_78-default-14-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.83-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_83-default-12-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.86-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_86-default-12-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.93-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_93-default-11-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.96-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_96-default-10-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-59.16-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_16-default-15-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.19-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_19-default-14-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.24-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_24-default-12-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.27-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_27-default-12-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.34-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_34-default-11-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.37-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_37-default-10-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.40-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_40-default-10-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.5-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_5-default-16-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-4_12_14-150_75-default / etc');
}
