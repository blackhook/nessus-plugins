#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2163-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(175417);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/12");

  script_cve_id(
    "CVE-2020-36691",
    "CVE-2022-43945",
    "CVE-2023-1611",
    "CVE-2023-1670",
    "CVE-2023-1855",
    "CVE-2023-1989",
    "CVE-2023-1990",
    "CVE-2023-1998",
    "CVE-2023-2124",
    "CVE-2023-2162",
    "CVE-2023-2483",
    "CVE-2023-30772"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2163-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2023:2163-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:2163-1 advisory.

  - An issue was discovered in the Linux kernel before 5.8. lib/nlattr.c allows attackers to cause a denial of
    service (unbounded recursion) via a nested Netlink policy with a back reference. (CVE-2020-36691)

  - The Linux kernel NFSD implementation prior to versions 5.19.17 and 6.0.2 are vulnerable to buffer
    overflow. NFSD tracks the number of pages held by each NFSD thread by combining the receive and send
    buffers of a remote procedure call (RPC) into a single array of pages. A client can force the send buffer
    to shrink by sending an RPC message over TCP with garbage data added at the end of the message. The RPC
    message with garbage data is still correctly formed according to the specification and is passed forward
    to handlers. Vulnerable code in NFSD is not expecting the oversized request and writes beyond the
    allocated buffer space. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H (CVE-2022-43945)

  - A use-after-free flaw was found in btrfs_search_slot in fs/btrfs/ctree.c in btrfs in the Linux Kernel.This
    flaw allows an attacker to crash the system and possibly cause a kernel information lea (CVE-2023-1611)

  - A flaw use after free in the Linux kernel Xircom 16-bit PCMCIA (PC-card) Ethernet driver was found.A local
    user could use this flaw to crash the system or potentially escalate their privileges on the system.
    (CVE-2023-1670)

  - A use-after-free flaw was found in xgene_hwmon_remove in drivers/hwmon/xgene-hwmon.c in the Hardware
    Monitoring Linux Kernel Driver (xgene-hwmon). This flaw could allow a local attacker to crash the system
    due to a race problem. This vulnerability could even lead to a kernel information leak problem.
    (CVE-2023-1855)

  - A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In
    this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on
    hdev devices. (CVE-2023-1989)

  - A use-after-free flaw was found in ndlc_remove in drivers/nfc/st-nci/ndlc.c in the Linux Kernel. This flaw
    could allow an attacker to crash the system due to a race problem. (CVE-2023-1990)

  - The Linux kernel allows userspace processes to enable mitigations by calling prctl with
    PR_SET_SPECULATION_CTRL which disables the speculation feature as well as by using seccomp. We had noticed
    that on VMs of at least one major cloud provider, the kernel still left the victim process exposed to
    attacks in some cases even after enabling the spectre-BTI mitigation with prctl. The same behavior can be
    observed on a bare-metal machine when forcing the mitigation to IBRS on boot command line. This happened
    because when plain IBRS was enabled (not enhanced IBRS), the kernel had some logic that determined that
    STIBP was not needed. The IBRS bit implicitly protects against cross-thread branch target injection.
    However, with legacy IBRS, the IBRS bit was cleared on returning to userspace, due to performance reasons,
    which disabled the implicit STIBP and left userspace threads vulnerable to cross-thread branch target
    injection against which STIBP protects. (CVE-2023-1998)

  - An out-of-bounds memory access flaw was found in the Linux kernel's XFS file system in how a user restores
    an XFS image after failure (with a dirty log journal). This flaw allows a local user to crash or
    potentially escalate their privileges on the system. (CVE-2023-2124) (CVE-2023-2124)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - The Linux kernel before 6.2.9 has a race condition and resultant use-after-free in
    drivers/power/supply/da9150-charger.c if a physically proximate attacker unplugs a device.
    (CVE-2023-30772)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211037");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029351.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30772");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1670");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_159-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.159.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.159.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.159.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.159.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_159-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
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
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
