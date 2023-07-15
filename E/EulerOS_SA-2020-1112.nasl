#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133913);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-3180",
    "CVE-2016-2085",
    "CVE-2017-18549",
    "CVE-2017-18550",
    "CVE-2018-12207",
    "CVE-2018-5995",
    "CVE-2018-7273",
    "CVE-2019-0155",
    "CVE-2019-11085",
    "CVE-2019-11135",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-14901",
    "CVE-2019-18660",
    "CVE-2019-19045",
    "CVE-2019-19078",
    "CVE-2019-19227",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19525",
    "CVE-2019-19534",
    "CVE-2019-19536",
    "CVE-2019-19768",
    "CVE-2019-19813",
    "CVE-2019-19922",
    "CVE-2019-19965",
    "CVE-2019-19966",
    "CVE-2019-20054",
    "CVE-2019-20095",
    "CVE-2019-5108",
    "CVE-2019-9458"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2020-1112)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):** DISPUTED ** In
    kernel/compat.c in the Linux kernel before 3.17, as
    used in Google Chrome OS and other products, there is a
    possible out-of-bounds read. restart_syscall uses
    uninitialized data when restarting
    compat_sys_nanosleep. NOTE: this is disputed because
    the code path is unreachable.(CVE-2014-3180)A heap
    overflow flaw was found in the Linux kernel, all
    versions 3.x.x and 4.x.x before 4.18.0, in Marvell WiFi
    chip driver. The vulnerability allows a remote attacker
    to cause a system crash, resulting in a denial of
    service, or execute arbitrary code. The highest threat
    with this vulnerability is with the availability of the
    system. If code execution occurs, the code will run
    with the permissions of root. This will affect both
    confidentiality and integrity of files on the
    system.(CVE-2019-14901)A heap-based buffer overflow
    vulnerability was found in the Linux kernel, version
    kernel-2.6.32, in Marvell WiFi chip driver. A remote
    attacker could cause a denial of service (system crash)
    or, possibly execute arbitrary code, when the
    lbs_ibss_join_existing function is called after a STA
    connects to an AP.(CVE-2019-14896)A memory leak in the
    ath10k_usb_hif_tx_sg() function in drivers/
    net/wireless/ath/ath10k/usb.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    usb_submit_urb() failures, aka
    CID-b8d17e7d93d2.(CVE-2019-19078)A memory leak in the
    mlx5_fpga_conn_create_cq() function in drivers/
    net/ethernet/mellanox/mlx5/core/fpga/conn.c in the
    Linux kernel before 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    mlx5_vector2eqn() failures, aka
    CID-c8c2a057fdc7.(CVE-2019-19045)A stack-based buffer
    overflow was found in the Linux kernel, version
    kernel-2.6.32, in Marvell WiFi chip driver. An attacker
    is able to cause a denial of service (system crash) or,
    possibly execute arbitrary code, when a STA works in
    IBSS mode (allows connecting stations together without
    the use of an AP) and connects to another
    STA.(CVE-2019-14897)An out-of-bounds memory write issue
    was found in the Linux Kernel, version 3.13 through
    5.4, in the way the Linux kernel's KVM hypervisor
    handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request
    to get CPUID features emulated by the KVM hypervisor. A
    user or process able to access the '/dev/kvm' device
    could use this flaw to crash the system, resulting in a
    denial of service.(CVE-2019-19332)Improper invalidation
    for page table updates by a virtual guest operating
    system for multiple Intel(R) Processors may allow an
    authenticated user to potentially enable denial of
    service of the host system via local
    access.(CVE-2018-12207)In the Android kernel in the
    video driver there is a use after free due to a race
    condition. This could lead to local escalation of
    privilege with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.(CVE-2019-9458)In the AppleTalk subsystem
    in the Linux kernel before 5.1, there is a potential
    NULL pointer dereference because register_snap_client
    may return NULL. This will lead to denial of service in
    net/appletalk/aarp.c and net/appletalk/ddp.c, as
    demonstrated by unregister_snap_client, aka
    CID-9804501fa122.(CVE-2019-19227)In the Linux kernel
    5.0.21, mounting a crafted btrfs filesystem image,
    performing some operations, and then making a syncfs
    system call can lead to a use-after-free in
    __mutex_lock in kernel/locking/mutex.c. This is related
    to mutex_can_spin_on_owner in kernel/locking/mutex.c,
    __btrfs_qgroup_free_meta in fs/btrfs/qgroup.c, and
    btrfs_insert_delayed_items in
    fs/btrfs/delayed-inode.c.(CVE-2019-19813)In the Linux
    kernel 5.4.0-rc2, there is a use-after-free (read) in
    the __blk_add_trace function in kernel/trace/blktrace.c
    (which is used to fill out a blk_io_trace structure and
    place it in a per-cpu sub-buffer).(CVE-2019-19768)In
    the Linux kernel before 5.0.6, there is a NULL pointer
    dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka
    CID-23da9588037e.(CVE-2019-20054)In the Linux kernel
    before 5.2.9, there is an info-leak bug that can be
    caused by a malicious USB device in the drivers/
    net/can/usb/peak_usb/pcan_usb_pro.c driver, aka
    CID-ead16e53c2f0.(CVE-2019-19536)In the Linux kernel
    before 5.3.11, there is an info-leak bug that can be
    caused by a malicious USB device in the drivers/
    net/can/usb/peak_usb/pcan_usb_core.c driver, aka
    CID-f7a1337f0d29.(CVE-2019-19534)In the Linux kernel
    before 5.3.6, there is a use-after-free bug that can be
    caused by a malicious USB device in the drivers/
    net/ieee802154/atusb.c driver, aka
    CID-7fd25e6fc035.(CVE-2019-19525)Insufficient access
    control in a subsystem for Intel (R) processor graphics
    in 6th, 7th, 8th and 9th Generation Intel(R) Core(TM)
    Processor Families Intel(R) Pentium(R) Processor J, N,
    Silver and Gold Series Intel(R) Celeron(R) Processor J,
    N, G3900 and G4900 Series Intel(R) Atom(R) Processor A
    and E3900 Series Intel(R) Xeon(R) Processor E3-1500 v5
    and v6, E-2100 and E-2200 Processor Families Intel(R)
    Graphics Driver for Windows before 26.20.100.6813 (DCH)
    or 26.20.100.6812 and before 21.20.x.5077
    (aka15.45.5077), i915 Linux Driver for Intel(R)
    Processor Graphics before versions 5.4-rc7, 5.3.11,
    4.19.84, 4.14.154, 4.9.201, 4.4.201 may allow an
    authenticated user to potentially enable escalation of
    privilege via local access.(CVE-2019-0155)Insufficient
    input validation in Kernel Mode Driver in Intel(R) i915
    Graphics for Linux before version 5.0 may allow an
    authenticated user to potentially enable escalation of
    privilege via local
    access.(CVE-2019-11085)kernel/sched/fair.c in the Linux
    kernel before 5.3.9, when cpu.cfs_quota_us is used
    (e.g., with Kubernetes), allows attackers to cause a
    denial of service against non-cpu-bound applications by
    generating a workload that triggers unwanted slice
    expiration, aka CID-de53fd7aedb1. (In other words,
    although this slice expiration would typically be seen
    with benign workloads, it is possible that an attacker
    could calculate how many stray requests are required to
    force an entire Kubernetes cluster into a
    low-performance state caused by slice expiration, and
    ensure that a DDoS attack sent that number of stray
    requests. An attack does not affect the stability of
    the kernel it only causes mismanagement of application
    execution.)(CVE-2019-19922)The evm_verify_hmac function
    in security/integrity/evm/evm_main.c in the Linux
    kernel before 4.5 does not properly copy data, which
    makes it easier for local users to forge MAC values via
    a timing side-channel attack.(CVE-2016-2085)The
    pcpu_embed_first_chunk function in mm/percpu.c in the
    Linux kernel through 4.14.14 allows local users to
    obtain sensitive address information by reading dmesg
    data from a 'pages/cpu' printk call.(CVE-2018-5995)TSX
    Asynchronous Abort condition on some CPUs utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access.(CVE-2019-11135)An issue was
    discovered in drivers/scsi/aacraid/commctrl.c in the
    Linux kernel before 4.13. There is potential exposure
    of kernel stack memory because aac_send_raw_srb does
    not initialize the reply structure.(CVE-2017-18549)An
    issue was discovered in drivers/scsi/aacraid/commctrl.c
    in the Linux kernel before 4.13. There is potential
    exposure of kernel stack memory because
    aac_get_hba_info does not initialize the hbainfo
    structure.(CVE-2017-18550)In the Linux kernel through
    4.15.4, the floppy driver reveals the addresses of
    kernel functions and global variables using printk
    calls within the function show_floppy in
    drivers/block/floppy.c. An attacker can read this
    information from dmesg and use the addresses to find
    the locations of kernel code and data and bypass kernel
    security protections such as KASLR.(CVE-2018-7273)A
    heap-based buffer overflow was discovered in the Linux
    kernel, all versions 3.x.x and 4.x.x before 4.18.0, in
    Marvell WiFi chip driver. The flaw could occur when the
    station attempts a connection negotiation during the
    handling of the remote devices country settings. This
    could allow the remote device to cause a denial of
    service (system crash) or possibly execute arbitrary
    code.(CVE-2019-14895)The Linux kernel before 5.4.1 on
    powerpc allows Information Exposure because the
    Spectre-RSB mitigation is not in place for all
    applicable CPUs, aka CID-39e72bf96f58. This is related
    to arch/powerpc/kernel/entry_64.S and
    arch/powerpc/kernel/security.c.(CVE-2019-18660)In the
    Linux kernel 5.0.21, mounting a crafted ext4 filesystem
    image, performing some operations, and unmounting can
    lead to a use-after-free in ext4_put_super in
    fs/ext4/super.c, related to dump_orphan_list in
    fs/ext4/super.c.(CVE-2019-19447)In the Linux kernel
    through 5.4.6, there is a NULL pointer dereference in
    drivers/scsi/libsas/sas_discover.c because of
    mishandling of port disconnection during discovery,
    related to a PHY down race condition, aka
    CID-f70267f379b5.(CVE-2019-19965)In the Linux kernel
    before 5.1.6, there is a use-after-free in cpia2_exit()
    in drivers/media/usb/cpia2/cpia2_v4l.c that will cause
    denial of service, aka
    CID-dea37a972655.(CVE-2019-19966)An exploitable
    denial-of-service vulnerability exists in the Linux
    kernel prior to mainline 5.3. An attacker could exploit
    this vulnerability by triggering AP to send IAPP
    location updates for stations before the required
    authentication process has completed. This could lead
    to different denial-of-service scenarios, either by
    causing CAM table attacks, or by leading to traffic
    flapping if faking already existing clients in other
    nearby APs of the same wireless infrastructure. An
    attacker can forge Authentication and Association
    Request packets to trigger this
    vulnerability.(CVE-2019-5108)mwifiex_tm_cmd in drivers/
    net/wireless/marvell/mwifiex/cfg80211.c in the Linux
    kernel before 5.1.6 has some error-handling cases that
    did not free allocated hostcmd memory, aka
    CID-003b686ace82. This will cause a memory leak and
    denial of service.(CVE-2019-20095)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1112
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51adc7d4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.5.h408.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h408.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h408.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h408.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h408.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h408.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h408.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
