#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3408-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165501);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2021-4203",
    "CVE-2022-1012",
    "CVE-2022-2588",
    "CVE-2022-2639",
    "CVE-2022-2663",
    "CVE-2022-2977",
    "CVE-2022-3028",
    "CVE-2022-20368",
    "CVE-2022-20369",
    "CVE-2022-21385",
    "CVE-2022-26373",
    "CVE-2022-29581",
    "CVE-2022-36879",
    "CVE-2022-39188"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3408-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2022:3408-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:3408-1 advisory.

  - An issue was discovered in the Linux kernel through 5.16.11. The mixed IPID assignment method with the
    hash-based IPID assignment policy allows an off-path attacker to inject data into a victim's TCP session
    or terminate that session. (CVE-2020-36516)

  - A use-after-free read flaw was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
    SO_PEERGROUPS race with listen() (and connect()) in the Linux kernel. In this flaw, an attacker with a
    user privileges may crash the system or leak internal kernel information. (CVE-2021-4203)

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - Product: AndroidVersions: Android kernelAndroid ID: A-224546354References: Upstream kernel
    (CVE-2022-20368)

  - In v4l2_m2m_querybuf of v4l2-mem2mem.c, there is a possible out of bounds write due to improper input
    validation. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-223375145References: Upstream kernel (CVE-2022-20369)

  - A flaw in net_rds_alloc_sgs() in Oracle Linux kernels allows unprivileged local users to crash the
    machine. CVSS 3.1 Base Score 6.2 (Availability impacts). CVSS Vector
    (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) (CVE-2022-21385)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

  - Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow
    an authorized user to potentially enable information disclosure via local access. (CVE-2022-26373)

  - An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of
    actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size()
    function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-2639)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to
    cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14
    and later versions. (CVE-2022-29581)

  - A flaw was found in the Linux kernel implementation of proxied virtualized TPM devices. On a system where
    virtualized TPM devices are configured (this is not the default) a local attacker can create a use-after-
    free and create a situation where it may be possible to escalate privileges on the system. (CVE-2022-2977)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203107");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012386.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cfce971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39188");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29581");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150100_197_123-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-devel-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-macros-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-source-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-syms-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'reiserfs-kmp-default-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-syms-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-devel-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-macros-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-source-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-debug-base-4.12.14-150100.197.123.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-default-man-4.12.14-150100.197.123.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-kvmsmall-base-4.12.14-150100.197.123.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-4.12.14-150100.197.123.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-base-4.12.14-150100.197.123.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-devel-4.12.14-150100.197.123.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-livepatch-devel-4.12.14-150100.197.123.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-zfcpdump-man-4.12.14-150100.197.123.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-debug-base-4.12.14-150100.197.123.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-man-4.12.14-150100.197.123.1', 'cpu':'s390x', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-base-4.12.14-150100.197.123.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-4.12.14-150100.197.123.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-base-4.12.14-150100.197.123.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-devel-4.12.14-150100.197.123.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-livepatch-devel-4.12.14-150100.197.123.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-zfcpdump-man-4.12.14-150100.197.123.1', 'cpu':'s390x', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-default-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'dlm-kmp-default-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'gfs2-kmp-default-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ocfs2-kmp-default-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'kernel-default-livepatch-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-default-livepatch-devel-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-livepatch-4_12_14-150100_197_123-default-1-150100.3.3.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-man-4.12.14-150100.197.123.1', 'sp':'1', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'reiserfs-kmp-default-4.12.14-150100.197.123.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
