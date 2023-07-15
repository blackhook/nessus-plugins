##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2111-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162399);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2017-13695",
    "CVE-2018-7755",
    "CVE-2019-19377",
    "CVE-2019-20811",
    "CVE-2020-26541",
    "CVE-2021-20292",
    "CVE-2021-20321",
    "CVE-2021-33061",
    "CVE-2021-38208",
    "CVE-2021-39711",
    "CVE-2021-43389",
    "CVE-2022-1011",
    "CVE-2022-1184",
    "CVE-2022-1353",
    "CVE-2022-1419",
    "CVE-2022-1516",
    "CVE-2022-1652",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21127",
    "CVE-2022-21166",
    "CVE-2022-21180",
    "CVE-2022-21499",
    "CVE-2022-22942",
    "CVE-2022-28748",
    "CVE-2022-30594"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2111-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2022:2111-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:2111-1 advisory.

  - The acpi_ns_evaluate() function in drivers/acpi/acpica/nseval.c in the Linux kernel through 4.12.9 does
    not flush the operand cache and causes a kernel stack dump, which allows local users to obtain sensitive
    information from kernel memory and bypass the KASLR protection mechanism (in the kernel through 4.9) via a
    crafted ACPI table. (CVE-2017-13695)

  - An issue was discovered in the fd_locked_ioctl function in drivers/block/floppy.c in the Linux kernel
    through 4.15.7. The floppy driver will copy a kernel pointer to user memory in response to the FDGETPRM
    ioctl. An attacker can send the FDGETPRM ioctl and use the obtained kernel pointer to discover the
    location of kernel code and data and bypass kernel security protections such as KASLR. (CVE-2018-7755)

  - In the Linux kernel 5.0.21, mounting a crafted btrfs filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in btrfs_queue_work in fs/btrfs/async-thread.c. (CVE-2019-19377)

  - An issue was discovered in the Linux kernel before 5.0.6. In rx_queue_add_kobject() and
    netdev_queue_add_kobject() in net/core/net-sysfs.c, a reference count is mishandled, aka CID-a3e23f719f5c.
    (CVE-2019-20811)

  - The Linux kernel through 5.8.13 does not properly enforce the Secure Boot Forbidden Signature Database
    (aka dbx) protection mechanism. This affects certs/blacklist.c and certs/system_keyring.c.
    (CVE-2020-26541)

  - There is a flaw reported in the Linux kernel in versions before 5.9 in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker with a local account with a root privilege, can leverage this vulnerability to
    escalate privileges and execute code in the context of the kernel. (CVE-2021-20292)

  - A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users
    do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.
    (CVE-2021-20321)

  - Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an
    authenticated user to potentially enable denial of service via local access. (CVE-2021-33061)

  - net/nfc/llcp_sock.c in the Linux kernel before 5.12.10 allows local unprivileged users to cause a denial
    of service (NULL pointer dereference and BUG) by making a getsockname call after a certain type of failure
    of a bind call. (CVE-2021-38208)

  - In bpf_prog_test_run_skb of test_run.c, there is a possible out of bounds read due to Incorrect Size
    Value. This could lead to local information disclosure with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-154175781References: Upstream kernel (CVE-2021-39711)

  - An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in
    the detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (CVE-2021-43389)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - The root cause of this vulnerability is that the ioctl$DRM_IOCTL_MODE_DESTROY_DUMB can decrease refcount
    of *drm_vgem_gem_object *(created in *vgem_gem_dumb_create*) concurrently, and *vgem_gem_dumb_create *will
    access the freed drm_vgem_gem_object. (CVE-2022-1419)

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

  - KGDB and KDB allow read and write access to kernel memory, and thus should be restricted during lockdown.
    An attacker with access to a serial port could trigger the debugger so it is important that the debugger
    respect the lockdown mode when/if it is triggered. (CVE-2022-21499)

  - kernel: failing usercopy allows for use-after-free exploitation (CVE-2022-22942)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1028340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1055710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1084513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1087082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200249");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-June/011310.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3864cb4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-7755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19377");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30594");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30594");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/18");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-4_12_14-150100_197_114-default");
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
    {'reference':'kernel-default-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-devel-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-macros-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-source-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-syms-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'reiserfs-kmp-default-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-syms-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'kernel-default-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-devel-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-macros-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-source-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'kernel-debug-base-4.12.14-150100.197.114.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-default-man-4.12.14-150100.197.114.2', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-kvmsmall-base-4.12.14-150100.197.114.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-4.12.14-150100.197.114.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-base-4.12.14-150100.197.114.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-devel-4.12.14-150100.197.114.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-vanilla-livepatch-devel-4.12.14-150100.197.114.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-zfcpdump-man-4.12.14-150100.197.114.2', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'kernel-debug-base-4.12.14-150100.197.114.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-default-man-4.12.14-150100.197.114.2', 'cpu':'s390x', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-kvmsmall-base-4.12.14-150100.197.114.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-4.12.14-150100.197.114.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-base-4.12.14-150100.197.114.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-devel-4.12.14-150100.197.114.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-vanilla-livepatch-devel-4.12.14-150100.197.114.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-zfcpdump-man-4.12.14-150100.197.114.2', 'cpu':'s390x', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-default-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'dlm-kmp-default-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'gfs2-kmp-default-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ocfs2-kmp-default-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'kernel-default-livepatch-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-default-livepatch-devel-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-livepatch-4_12_14-150100_197_114-default-1-150100.3.3.2', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.1']},
    {'reference':'kernel-default-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-base-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-devel-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-default-man-4.12.14-150100.197.114.2', 'sp':'1', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-obs-build-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'kernel-syms-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'reiserfs-kmp-default-4.12.14-150100.197.114.2', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']}
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
