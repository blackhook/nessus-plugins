##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2104-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162379);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2019-19377",
    "CVE-2020-26541",
    "CVE-2021-20321",
    "CVE-2021-33061",
    "CVE-2022-0168",
    "CVE-2022-1011",
    "CVE-2022-1158",
    "CVE-2022-1184",
    "CVE-2022-1353",
    "CVE-2022-1516",
    "CVE-2022-1652",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1966",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21127",
    "CVE-2022-21166",
    "CVE-2022-21180",
    "CVE-2022-28893",
    "CVE-2022-30594"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2104-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:2104-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:2104-1 advisory.

  - In the Linux kernel 5.0.21, mounting a crafted btrfs filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in btrfs_queue_work in fs/btrfs/async-thread.c. (CVE-2019-19377)

  - The Linux kernel through 5.8.13 does not properly enforce the Secure Boot Forbidden Signature Database
    (aka dbx) protection mechanism. This affects certs/blacklist.c and certs/system_keyring.c.
    (CVE-2020-26541)

  - A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users
    do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.
    (CVE-2021-20321)

  - Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an
    authenticated user to potentially enable denial of service via local access. (CVE-2021-33061)

  - A denial of service (DOS) issue was found in the Linux kernel's smb2_ioctl_query_info function in the
    fs/cifs/smb2ops.c Common Internet File System (CIFS) due to an incorrect return from the memdup_user
    function. This flaw allows a local, privileged (CAP_SYS_ADMIN) attacker to crash the system.
    (CVE-2022-0168)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A flaw was found in KVM. When updating a guest's page table entry, vm_pgoff was improperly used as the
    offset to get the page's pfn. As vaddr and vm_pgoff are controllable by user-mode processes, this flaw
    allows unprivileged local users on the host to write outside the userspace region and potentially corrupt
    the kernel, resulting in a denial of service condition. (CVE-2022-1158)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - A NULL pointer dereference flaw was found in the Linux kernel's X.25 set of standardized network protocols
    functionality in the way a user terminates their session using a simulated Ethernet card and continued
    usage of this connection. This flaw allows a local user to crash the system. (CVE-2022-1516)

  - Linux Kernel could allow a local attacker to execute arbitrary code on the system, caused by a concurrency
    use-after-free flaw in the bad_flp_intr function. By executing a specially-crafted program, an attacker
    could exploit this vulnerability to execute arbitrary code or cause a denial of service condition on the
    system. (CVE-2022-1652)

  - A race condition was found the Linux kernel in perf_event_open() which can be exploited by an unprivileged
    user to gain root privileges. The bug allows to build several exploit primitives such as kernel address
    information leak, arbitrary execution, etc. (CVE-2022-1729)

  - A flaw in Linux Kernel found in nfcmrvl_nci_unregister_dev() in drivers/nfc/nfcmrvl/main.c can lead to use
    after free both read or write when non synchronized between cleanup routine and firmware download routine.
    (CVE-2022-1734)

  - A use-after-free flaw was found in the Linux kernel's NFC core functionality due to a race condition
    between kobject creation and delete. This vulnerability allows a local attacker with CAP_NET_ADMIN
    privilege to leak kernel information. (CVE-2022-1974)

  - There is a sleep-in-atomic bug in /net/nfc/netlink.c that allows an attacker to crash the Linux kernel by
    simulating a nfc device from user-space. (CVE-2022-1975)

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

  - The SUNRPC subsystem in the Linux kernel through 5.17.2 can call xs_xprt_free before ensuring that sockets
    are in the intended state. (CVE-2022-28893)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1028340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200249");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-June/011302.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03ca89ed");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19377");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30594");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28893");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30594");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150200_24_115-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.115.1.150200.9.54.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-devel-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-macros-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-source-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-syms-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'reiserfs-kmp-default-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.115.1.150200.9.54.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-syms-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'kernel-default-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.115.1.150200.9.54.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.115.1.150200.9.54.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-devel-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-macros-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-source-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.115.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'cluster-md-kmp-default-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'dlm-kmp-default-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'gfs2-kmp-default-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ocfs2-kmp-default-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'kernel-default-livepatch-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-livepatch-5_3_18-150200_24_115-default-1-150200.5.3.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.115.1.150200.9.54.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'reiserfs-kmp-default-5.3.18-150200.24.115.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
