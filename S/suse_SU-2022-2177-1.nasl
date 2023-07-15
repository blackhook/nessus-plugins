##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2177-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162531);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/26");

  script_cve_id(
    "CVE-2019-19377",
    "CVE-2020-26541",
    "CVE-2021-33061",
    "CVE-2022-0168",
    "CVE-2022-1184",
    "CVE-2022-1652",
    "CVE-2022-1729",
    "CVE-2022-1966",
    "CVE-2022-1972",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-20008",
    "CVE-2022-20141",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21127",
    "CVE-2022-21166",
    "CVE-2022-21180",
    "CVE-2022-30594",
    "CVE-2022-32250"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2177-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:2177-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:2177-1 advisory.

  - In the Linux kernel 5.0.21, mounting a crafted btrfs filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in btrfs_queue_work in fs/btrfs/async-thread.c. (CVE-2019-19377)

  - The Linux kernel through 5.8.13 does not properly enforce the Secure Boot Forbidden Signature Database
    (aka dbx) protection mechanism. This affects certs/blacklist.c and certs/system_keyring.c.
    (CVE-2020-26541)

  - Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an
    authenticated user to potentially enable denial of service via local access. (CVE-2021-33061)

  - Linux Kernel could allow a local attacker to execute arbitrary code on the system, caused by a concurrency
    use-after-free flaw in the bad_flp_intr function. By executing a specially-crafted program, an attacker
    could exploit this vulnerability to execute arbitrary code or cause a denial of service condition on the
    system. (CVE-2022-1652)

  - kernel: race condition in perf_event_open leads to privilege escalation (CVE-2022-1729)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2022-32250. Reason: This candidate is a
    duplicate of CVE-2022-32250. Notes: All CVE users should reference CVE-2022-32250 instead of this
    candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2022-1966)

  - In mmc_blk_read_single of block.c, there is a possible way to read kernel heap memory due to uninitialized
    data. This could lead to local information disclosure if reading from an SD card that triggers errors,
    with no additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID: A-216481035References: Upstream kernel (CVE-2022-20008)

  - In ip_check_mc_rcu of igmp.c, there is a possible use after free due to improper locking. This could lead
    to local escalation of privilege when opening and closing inet sockets with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-112551163References: Upstream kernel (CVE-2022-20141)

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register read operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21127)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

  - Improper input validation for some Intel(R) Processors may allow an authenticated user to potentially
    cause a denial of service via local access. (CVE-2022-21180)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1055117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1061840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1103269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200604");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-June/011353.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84c0117c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19377");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32250");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32250");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'dlm-kmp-rt-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'gfs2-kmp-rt-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-devel-rt-5.3.18-150300.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-devel-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt_debug-devel-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-source-rt-5.3.18-150300.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-syms-rt-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'ocfs2-kmp-rt-5.3.18-150300.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
