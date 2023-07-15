#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3061-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164914);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2020-36516", "CVE-2022-36946");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3061-1");

  script_name(english:"SUSE SLES12 / SLES15 Security Update : kernel (Live Patch 10 for SLE 15 SP3) (SUSE-SU-2022:3061-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:3061-1 advisory.

  - An issue was discovered in the Linux kernel through 5.16.11. The mixed IPID assignment method with the
    hash-based IPID assignment policy allows an off-path attacker to inject data into a victim's TCP session
    or terminate that session. (CVE-2020-36516)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201941");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012117.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cd94395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36946");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150000_150_89-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150000_150_92-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150000_150_95-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150100_197_111-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150100_197_114-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150100_197_117-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_78-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150_86-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-197_102-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-197_105-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-197_108-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150200_24_112-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150200_24_115-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_43-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_46-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_49-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_54-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_60-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_63-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_68-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_71-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_76-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_87-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_102-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_107-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_86-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_93-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_96-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-24_99-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_24-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_27-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_34-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_37-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_40-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_103-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_106-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_110-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_113-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_116-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_121-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_124-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_127-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_91-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_98-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_102-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_105-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_83-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_93-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_96-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-95_99-default");
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
      '4.12.14-122.103-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_103-default-14-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.106-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_106-default-12-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.110-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_110-default-10-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.113-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_113-default-9-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.116-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_116-default-7-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.121-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_121-default-5-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.124-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_124-default-4-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.127-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_127-default-2-2.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.88-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_88-default-16-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.91-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_91-default-16-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-122.98-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-122_98-default-14-2.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
        ]
      },
      '4.12.14-150.78-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_78-default-13-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.83-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_83-default-9-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150.86-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150_86-default-8-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150000.150.89-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150000_150_89-default-7-150000.2.2', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150000.150.92-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150000_150_92-default-4-150000.2.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150000.150.95-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150000_150_95-default-2-150000.2.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15']}
        ]
      },
      '4.12.14-150100.197.111-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150100_197_111-default-7-150100.2.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-150100.197.114-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150100_197_114-default-4-150100.2.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-150100.197.117-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-150100_197_117-default-2-150100.2.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-197.102-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-197_102-default-13-150100.2.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-197.105-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-197_105-default-9-150100.2.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-197.108-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-4_12_14-197_108-default-8-150100.2.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']}
        ]
      },
      '4.12.14-95.102-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_102-default-2-2.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.12.14-95.105-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_105-default-2-2.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.12.14-95.83-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_83-default-13-2.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.12.14-95.88-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_88-default-9-2.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.12.14-95.93-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_93-default-8-2.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.12.14-95.96-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_96-default-7-2.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '4.12.14-95.99-default': {
        'pkgs': [
          {'reference':'kgraft-patch-4_12_14-95_99-default-4-2.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.4']}
        ]
      },
      '5.3.18-150200.24.112-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150200_24_112-default-7-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-150200.24.115-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150200_24_115-default-5-150200.2.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-150300.59.43-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_43-default-13-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.46-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_46-default-13-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.49-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_49-default-12-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.54-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_54-default-11-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.60-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_60-default-10-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.63-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_63-default-7-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.68-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_68-default-6-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.71-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_71-default-5-150300.2.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.76-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_76-default-4-150300.2.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-150300.59.87-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_87-default-3-150300.2.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-24.102-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_102-default-12-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.107-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_107-default-11-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.83-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_83-default-16-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.86-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_86-default-16-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.93-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_93-default-15-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.96-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_96-default-14-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-24.99-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-24_99-default-13-150200.2.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-59.24-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_24-default-16-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.27-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_27-default-16-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.34-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_34-default-15-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.37-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_37-default-14-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.40-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_40-default-14-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
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
