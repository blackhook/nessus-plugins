#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:1802-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174048);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2017-5753",
    "CVE-2022-4744",
    "CVE-2023-0394",
    "CVE-2023-1281",
    "CVE-2023-1513",
    "CVE-2023-1582",
    "CVE-2023-1637",
    "CVE-2023-1652",
    "CVE-2023-28327",
    "CVE-2023-28464",
    "CVE-2023-28466"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:1802-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:1802-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:1802-1 advisory.

  - Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized
    disclosure of information to an attacker with local user access via a side-channel analysis.
    (CVE-2017-5753)

  - A double-free flaw was found in the Linux kernel's TUN/TAP device driver functionality in how a user
    registers the device when the register_netdevice function fails (NETDEV_REGISTER notifier). This flaw
    allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-4744)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - Use After Free vulnerability in Linux kernel traffic control index filter (tcindex) allows Privilege
    Escalation. The imperfect hash area can be updated while packets are traversing, which will cause a use-
    after-free when 'tcf_exts_exec()' is called with the destroyed tcf_ext. A local attacker user can use this
    vulnerability to elevate its privileges to root. This issue affects Linux Kernel: from 4.14 before git
    commit ee059170b1f7e94e55fa6cadee544e176a6e59c2. (CVE-2023-1281)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - A race problem was found in fs/proc/task_mmu.c in the memory management sub-component in the Linux kernel.
    This issue may allow a local attacker with user privilege to cause a denial of service. (CVE-2023-1582)

  - A flaw that boot CPU could be vulnerable for the speculative execution behavior kind of attacks in the
    Linux kernel X86 CPU Power management options functionality was found in the way user resuming CPU from
    suspend-to-RAM. A local user could use this flaw to potentially get unauthorized access to some memory of
    the CPU similar to the speculative execution behavior kind of attacks. (CVE-2023-1637)

  - A use-after-free flaw was found in nfsd4_ssc_setup_dul in fs/nfsd/nfs4proc.c in the NFS filesystem in the
    Linux Kernel. This issue could allow a local attacker to crash the system or it may lead to a kernel
    information leak problem. (CVE-2023-1652)

  - hci_conn_cleanup in net/bluetooth/hci_conn.c in the Linux kernel through 6.2.9 has a use-after-free
    (observed in hci_conn_hash_flush) because of calls to hci_dev_put and hci_conn_put. There is a double free
    that may lead to privilege escalation. (CVE-2023-28464)

  - do_tls_getsockopt in net/tls/tls_main.c in the Linux kernel through 6.2.6 lacks a lock_sock call, leading
    to a race condition (with a resultant use-after-free or NULL pointer dereference). (CVE-2023-28466)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210050");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-April/028740.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28466");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5753");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28464");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150400.14.43.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.43.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.43.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.43.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.43.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.43.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.43.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.43.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.43.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.43.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.43.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / kernel-azure / etc');
}
