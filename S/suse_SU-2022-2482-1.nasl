##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2482-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(163379);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2022-1729", "CVE-2022-20154", "CVE-2022-21499");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2482-1");

  script_name(english:"SUSE SLES12 / SLES15 Security Update : kernel (Live Patch 0 for SLE 15 SP4) (SUSE-SU-2022:2482-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:2482-1 advisory.

  - A race condition was found the Linux kernel in perf_event_open() which can be exploited by an unprivileged
    user to gain root privileges. The bug allows to build several exploit primitives such as kernel address
    information leak, arbitrary execution, etc. (CVE-2022-1729)

  - In lock_sock_nested of sock.c, there is a possible use after free due to a race condition. This could lead
    to local escalation of privilege with System execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174846563References: Upstream
    kernel (CVE-2022-20154)

  - KGDB and KDB allow read and write access to kernel memory, and thus should be restricted during lockdown.
    An attacker with access to a serial port could trigger the debugger so it is important that the debugger
    respect the lockdown mode when/if it is triggered. (CVE-2022-21499)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200608");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-July/011615.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2845bc78");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21499");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21499");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150000_150_89-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_75-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_78-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_86-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-197_105-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-197_99-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_22-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_43-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_46-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_49-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_54-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_60-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_63-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_68-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_102-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_70-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_78-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_86-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_93-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_13-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_16-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_19-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_24-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_27-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_34-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_37-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_40-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_103-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_106-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_110-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_113-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_121-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_77-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_80-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_96-default");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3/4", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '4.12.14-122.103-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_103-default-12-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.106-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_106-default-10-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.110-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_110-default-8-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.113-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_113-default-7-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.121-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_121-default-3-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.77-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_77-default-18-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.80-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_80-default-17-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.83-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_83-default-16-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.88-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_88-default-14-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-150.75-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_75-default-16-150000.2.3', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.78-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_78-default-11-150000.2.3', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.86-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_86-default-6-150000.2.3', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150000.150.89-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150000_150_89-default-5-150000.2.3', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-197.105-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-197_105-default-7-150100.2.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-197.99-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-197_99-default-16-150100.2.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-95.88-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_88-default-7-2.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.12.14-95.96-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_96-default-5-2.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '5.14.21-150400.22-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_14_21-150400_22-default-3-150400.4.6.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
        ]
      },
      '5.3.18-150300.59.43-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_43-default-11-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.46-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_46-default-11-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.49-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_49-default-10-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.54-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_54-default-9-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.60-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_60-default-8-150300.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.63-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_63-default-5-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.68-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_68-default-4-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-24.102-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_102-default-10-150200.2.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.70-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_70-default-18-150200.2.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.78-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_78-default-16-150200.2.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.86-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_86-default-14-150200.2.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.93-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_93-default-13-150200.2.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-59.13-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_13-default-18-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.16-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_16-default-17-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.19-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_19-default-16-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.24-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_24-default-14-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.27-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_27-default-14-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.34-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_34-default-13-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.37-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_37-default-12-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.40-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_40-default-12-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-4_12_14-150000_150_89-default / etc');
}
