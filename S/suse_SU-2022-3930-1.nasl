#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3930-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167336);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2021-4037",
    "CVE-2022-2153",
    "CVE-2022-2964",
    "CVE-2022-3521",
    "CVE-2022-3524",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3565",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-3621",
    "CVE-2022-3628",
    "CVE-2022-3629",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-43750"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3930-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2022:3930-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3930-1 advisory.

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet
    Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.
    (CVE-2022-2964)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function kcm_tx_work of the file net/kcm/kcmsock.c of the component kcm. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211018 is the identifier
    assigned to this vulnerability. (CVE-2022-3521)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_bmap_lookup_at_level of the file fs/nilfs2/inode.c of the component nilfs2. The manipulation leads
    to null pointer dereference. It is possible to launch the attack remotely. It is recommended to apply a
    patch to fix this issue. The identifier of this vulnerability is VDB-211920. (CVE-2022-3621)

  - A buffer overflow flaw was found in the Linux kernel Broadcom Full MAC Wi-Fi driver. This issue occurs
    when a user connects to a malicious USB device. This can allow a local user to crash the system or
    escalate their privileges. (CVE-2022-3628)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this
    vulnerability. (CVE-2022-3629)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function nilfs_attach_log_writer of the file fs/nilfs2/segment.c of the component BPF. The
    manipulation leads to memory leak. The attack may be initiated remotely. It is recommended to apply a
    patch to fix this issue. The identifier VDB-211961 was assigned to this vulnerability. (CVE-2022-3646)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211992. (CVE-2022-3649)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204868");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012869.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ec896ca");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43750");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3628");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/13");

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
    {'reference':'cluster-md-kmp-rt-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.106.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.106.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.106.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
