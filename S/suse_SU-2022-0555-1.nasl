#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0555-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158337);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2020-28097",
    "CVE-2021-3564",
    "CVE-2021-4083",
    "CVE-2021-4135",
    "CVE-2021-4149",
    "CVE-2021-4197",
    "CVE-2021-4202",
    "CVE-2021-39648",
    "CVE-2021-39657",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2022-0322",
    "CVE-2022-0330",
    "CVE-2022-0435",
    "CVE-2022-22942",
    "CVE-2022-24448"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0555-1");

  script_name(english:"SUSE SLES12 Security Update : the Linux RT Kernel (SUSE-SU-2022:0555-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0555-1 advisory.

  - The vgacon subsystem in the Linux kernel before 5.8.10 mishandles software scrollback. There is a
    vgacon_scrolldelta out-of-bounds read, aka CID-973c096f6a85. (CVE-2020-28097)

  - A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. This flaw affects all the Linux kernel versions starting from 3.13. (CVE-2021-3564)

  - In gadget_dev_desc_UDC_show of configfs.c, there is a possible disclosure of kernel heap memory due to a
    race condition. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-160822094References: Upstream kernel (CVE-2021-39648)

  - In ufshcd_eh_device_reset_handler of ufshcd.c, there is a possible out of bounds read due to a missing
    bounds check. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-194696049References: Upstream kernel (CVE-2021-39657)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A memory leak vulnerability was found in the Linux kernel's eBPF for the Simulated networking device
    driver in the way user uses BPF for the device such that function nsim_map_alloc_elem being called. A
    local user could use this flaw to get unauthorized access to some data. (CVE-2021-4135)

  - A vulnerability was found in btrfs_alloc_tree_b in fs/btrfs/extent-tree.c in the Linux kernel due to an
    improper lock operation in btrfs. In this flaw, a user with a local privilege may cause a denial of
    service (DOS) due to a deadlock problem. (CVE-2021-4149)

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A use-after-free flaw was found in nci_request in net/nfc/nci/core.c in NFC Controller Interface (NCI) in
    the Linux kernel. This flaw could allow a local attacker with user privileges to cause a data race problem
    while the device is getting removed, leading to a privilege escalation problem. (CVE-2021-4202)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - A flaw was found in the sctp_make_strreset_req function in net/sctp/sm_make_chunk.c in the SCTP network
    protocol in the Linux kernel with a local user privilege access. In this flaw, an attempt to use more
    buffer than is allocated triggers a BUG_ON issue, leading to a denial of service (DOS). (CVE-2022-0322)

  - A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the
    way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-0330)

  - A stack overflow flaw was found in the Linux kernel's TIPC protocol functionality in the way a user sends
    a packet with malicious content where the number of domain member nodes is higher than the 64 allowed.
    This flaw allows a remote user to crash the system or possibly escalate their privileges if they have
    access to the TIPC network. (CVE-2022-0435)

  - kernel: failing usercopy allows for use-after-free exploitation (CVE-2022-22942)

  - An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the
    O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a
    regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file
    descriptor. (CVE-2022-24448)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195612");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-February/010290.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba627bdb");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24448");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.78.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.78.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.78.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
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
