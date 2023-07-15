##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2424-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(163360);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2021-4157",
    "CVE-2021-26341",
    "CVE-2022-1012",
    "CVE-2022-1679",
    "CVE-2022-20132",
    "CVE-2022-20154",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-33981",
    "CVE-2022-34918"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2424-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:2424-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:2424-1 advisory.

  - Some AMD CPUs may transiently execute beyond unconditional direct branches, which may potentially result
    in data leakage. (CVE-2021-26341)

  - An out of memory bounds write flaw (1 or 2 bytes of memory) in the Linux kernel NFS subsystem was found in
    the way users use mirroring (replication of files with NFS). A user, having access to the NFS mount, could
    potentially use this flaw to crash the system or escalate privileges on the system. (CVE-2021-4157)

  - kernel: Small table perturb size in the TCP source port generation algorithm can lead to information leak
    (CVE-2022-1012)

  - A use-after-free flaw was found in the Linux kernel's Atheros wireless adapter driver in the way a user
    forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local
    user to crash or potentially escalate their privileges on the system. (CVE-2022-1679)

  - In lg_probe and related functions of hid-lg.c and other USB HID files, there is a possible out of bounds
    read due to improper input validation. This could lead to local information disclosure if a malicious USB
    HID device were plugged in, with no additional execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-188677105References: Upstream
    kernel (CVE-2022-20132)

  - In lock_sock_nested of sock.c, there is a possible use after free due to a race condition. This could lead
    to local escalation of privilege with System execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174846563References: Upstream
    kernel (CVE-2022-20154)

  - AMD microprocessor families 15h to 18h are affected by a new Spectre variant that is able to bypass their
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can
    hijack return instructions to achieve arbitrary speculative code execution under certain
    microarchitecture-dependent conditions. (CVE-2022-29900)

  - Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can
    hijack return instructions to achieve arbitrary speculative code execution under certain
    microarchitecture-dependent conditions. (CVE-2022-29901)

  - drivers/block/floppy.c in the Linux kernel before 5.17.6 is vulnerable to a denial of service, because of
    a concurrency use-after-free flaw after deallocating raw_cmd in the raw_cmd_ioctl function.
    (CVE-2022-33981)

  - An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init
    (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different
    vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an
    unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data
    in net/netfilter/nf_tables_api.c. (CVE-2022-34918)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201222");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-July/011577.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cd02af7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20132");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34918");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4157");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter nft_set_elem_init Heap Overflow Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmrt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cluster-md-kmp-rt-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'dlm-kmp-rt-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'gfs2-kmp-rt-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-devel-rt-5.3.18-150300.96.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-devel-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt_debug-devel-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-source-rt-5.3.18-150300.96.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-syms-rt-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'ocfs2-kmp-rt-5.3.18-150300.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']}
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
