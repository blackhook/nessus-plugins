#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-0007.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68177);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2010-2492",
    "CVE-2010-3067",
    "CVE-2010-3078",
    "CVE-2010-3080",
    "CVE-2010-3298",
    "CVE-2010-3477",
    "CVE-2010-3861",
    "CVE-2010-3865",
    "CVE-2010-3874",
    "CVE-2010-3876",
    "CVE-2010-3880",
    "CVE-2010-4072",
    "CVE-2010-4073",
    "CVE-2010-4074",
    "CVE-2010-4075",
    "CVE-2010-4077",
    "CVE-2010-4079",
    "CVE-2010-4080",
    "CVE-2010-4081",
    "CVE-2010-4082",
    "CVE-2010-4083",
    "CVE-2010-4158",
    "CVE-2010-4160",
    "CVE-2010-4162",
    "CVE-2010-4163",
    "CVE-2010-4242",
    "CVE-2010-4248",
    "CVE-2010-4249",
    "CVE-2010-4263",
    "CVE-2010-4525",
    "CVE-2010-4668"
  );
  script_bugtraq_id(
    42237,
    42529,
    43022,
    43062,
    43226,
    43353,
    43806,
    43809,
    43817,
    44427,
    44549,
    44630,
    44661,
    44665,
    44758,
    44762,
    44793,
    45014,
    45028,
    45037,
    45054,
    45058,
    45059,
    45062,
    45063,
    45073,
    45074,
    45208,
    45660,
    45676
  );
  script_xref(name:"RHSA", value:"2011:0007");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-0007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-0007 advisory.

  - Buffer overflow in the ecryptfs_uid_hash macro in fs/ecryptfs/messaging.c in the eCryptfs subsystem in the
    Linux kernel before 2.6.35 might allow local users to gain privileges or cause a denial of service (system
    crash) via unspecified vectors. (CVE-2010-2492)

  - The drm_ioctl function in drivers/gpu/drm/drm_drv.c in the Direct Rendering Manager (DRM) subsystem in the
    Linux kernel before 2.6.27.53, 2.6.32.x before 2.6.32.21, 2.6.34.x before 2.6.34.6, and 2.6.35.x before
    2.6.35.4 allows local users to obtain potentially sensitive information from kernel memory by requesting a
    large memory-allocation amount. (CVE-2010-2803)

  - The cfg80211_wext_giwessid function in net/wireless/wext-compat.c in the Linux kernel before
    2.6.36-rc3-next-20100831 does not properly initialize certain structure members, which allows local users
    to leverage an off-by-one error in the ioctl_standard_iw_point function in net/wireless/wext-core.c, and
    obtain potentially sensitive information from kernel heap memory, via vectors involving an SIOCGIWESSID
    ioctl call that specifies a large buffer size. (CVE-2010-2955)

  - drivers/gpu/drm/i915/i915_gem.c in the Graphics Execution Manager (GEM) in the Intel i915 driver in the
    Direct Rendering Manager (DRM) subsystem in the Linux kernel before 2.6.36 does not properly validate
    pointers to blocks of memory, which allows local users to write to arbitrary kernel memory locations, and
    consequently gain privileges, via crafted use of the ioctl interface, related to (1) pwrite and (2) pread
    operations. (CVE-2010-2962)

  - Integer overflow in the do_io_submit function in fs/aio.c in the Linux kernel before
    2.6.36-rc4-next-20100915 allows local users to cause a denial of service or possibly have unspecified
    other impact via crafted use of the io_submit system call. (CVE-2010-3067)

  - The xfs_ioc_fsgetxattr function in fs/xfs/linux-2.6/xfs_ioctl.c in the Linux kernel before 2.6.36-rc4 does
    not initialize a certain structure member, which allows local users to obtain potentially sensitive
    information from kernel stack memory via an ioctl call. (CVE-2010-3078)

  - kernel/trace/ftrace.c in the Linux kernel before 2.6.35.5, when debugfs is enabled, does not properly
    handle interaction between mutex possession and llseek operations, which allows local users to cause a
    denial of service (NULL pointer dereference and outage of all function tracing files) via an lseek call on
    a file descriptor associated with the set_ftrace_filter file. (CVE-2010-3079)

  - Double free vulnerability in the snd_seq_oss_open function in sound/core/seq/oss/seq_oss_init.c in the
    Linux kernel before 2.6.36-rc4 might allow local users to cause a denial of service or possibly have
    unspecified other impact via an unsuccessful attempt to open the /dev/sequencer device. (CVE-2010-3080)

  - The compat_alloc_user_space functions in include/asm/compat.h files in the Linux kernel before
    2.6.36-rc4-git2 on 64-bit platforms do not properly allocate the userspace memory required for the 32-bit
    compatibility layer, which allows local users to gain privileges by leveraging the ability of the
    compat_mc_getsockopt function (aka the MCAST_MSFILTER getsockopt support) to control a certain length
    value, related to a stack pointer underflow issue, as exploited in the wild in September 2010.
    (CVE-2010-3081)

  - Buffer overflow in the niu_get_ethtool_tcam_all function in drivers/net/niu.c in the Linux kernel before
    2.6.36-rc4 allows local users to cause a denial of service or possibly have unspecified other impact via
    the ETHTOOL_GRXCLSRLALL ethtool command. (CVE-2010-3084)

  - The hso_get_count function in drivers/net/usb/hso.c in the Linux kernel before 2.6.36-rc5 does not
    properly initialize a certain structure member, which allows local users to obtain potentially sensitive
    information from kernel stack memory via a TIOCGICOUNT ioctl call. (CVE-2010-3298)

  - The IA32 system call emulation functionality in arch/x86/ia32/ia32entry.S in the Linux kernel before
    2.6.36-rc4-git2 on the x86_64 platform does not zero extend the %eax register after the 32-bit entry path
    to ptrace is used, which allows local users to gain privileges by triggering an out-of-bounds access to
    the system call table using the %rax register. NOTE: this vulnerability exists because of a CVE-2007-4573
    regression. (CVE-2010-3301)

  - The sctp_packet_config function in net/sctp/output.c in the Linux kernel before 2.6.35.6 performs
    extraneous initializations of packet data structures, which allows remote attackers to cause a denial of
    service (panic) via a certain sequence of SCTP traffic. (CVE-2010-3432)

  - Integer signedness error in the pkt_find_dev_from_minor function in drivers/block/pktcdvd.c in the Linux
    kernel before 2.6.36-rc6 allows local users to obtain sensitive information from kernel memory or cause a
    denial of service (invalid pointer dereference and system crash) via a crafted index value in a
    PKT_CTRL_CMD_STATUS ioctl call. (CVE-2010-3437)

  - Multiple integer overflows in the snd_ctl_new function in sound/core/control.c in the Linux kernel before
    2.6.36-rc5-next-20100929 allow local users to cause a denial of service (heap memory corruption) or
    possibly have unspecified other impact via a crafted (1) SNDRV_CTL_IOCTL_ELEM_ADD or (2)
    SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl call. (CVE-2010-3442)

  - The tcf_act_police_dump function in net/sched/act_police.c in the actions implementation in the network
    queueing functionality in the Linux kernel before 2.6.36-rc4 does not properly initialize certain
    structure members, which allows local users to obtain potentially sensitive information from kernel memory
    via vectors involving a dump operation. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2010-2942. (CVE-2010-3477)

  - The KVM implementation in the Linux kernel before 2.6.36 does not properly reload the FS and GS segment
    registers, which allows host OS users to cause a denial of service (host OS crash) via a KVM_RUN ioctl
    call in conjunction with a modified Local Descriptor Table (LDT). (CVE-2010-3698)

  - The sctp_auth_asoc_get_hmac function in net/sctp/auth.c in the Linux kernel before 2.6.36 does not
    properly validate the hmac_ids array of an SCTP peer, which allows remote attackers to cause a denial of
    service (memory corruption and panic) via a crafted value in the last element of this array.
    (CVE-2010-3705)

  - The ethtool_get_rxnfc function in net/core/ethtool.c in the Linux kernel before 2.6.36 does not initialize
    a certain block of heap memory, which allows local users to obtain potentially sensitive information via
    an ETHTOOL_GRXCLSRLALL ethtool command with a large info.rule_cnt value, a different vulnerability than
    CVE-2010-2478. (CVE-2010-3861)

  - Integer overflow in the rds_rdma_pages function in net/rds/rdma.c in the Linux kernel allows local users
    to cause a denial of service (crash) and possibly execute arbitrary code via a crafted iovec struct in a
    Reliable Datagram Sockets (RDS) request, which triggers a buffer overflow. (CVE-2010-3865)

  - Heap-based buffer overflow in the bcm_connect function in net/can/bcm.c (aka the Broadcast Manager) in the
    Controller Area Network (CAN) implementation in the Linux kernel before 2.6.36.2 on 64-bit platforms might
    allow local users to cause a denial of service (memory corruption) via a connect operation.
    (CVE-2010-3874)

  - net/packet/af_packet.c in the Linux kernel before 2.6.37-rc2 does not properly initialize certain
    structure members, which allows local users to obtain potentially sensitive information from kernel stack
    memory by leveraging the CAP_NET_RAW capability to read copies of the applicable structures.
    (CVE-2010-3876)

  - net/ipv4/inet_diag.c in the Linux kernel before 2.6.37-rc2 does not properly audit INET_DIAG bytecode,
    which allows local users to cause a denial of service (kernel infinite loop) via crafted
    INET_DIAG_REQ_BYTECODE instructions in a netlink message that contains multiple attribute elements, as
    demonstrated by INET_DIAG_BC_JMP instructions. (CVE-2010-3880)

  - The rds_page_copy_user function in net/rds/page.c in the Reliable Datagram Sockets (RDS) protocol
    implementation in the Linux kernel before 2.6.36 does not properly validate addresses obtained from user
    space, which allows local users to gain privileges via crafted use of the sendmsg and recvmsg system
    calls. (CVE-2010-3904)

  - The copy_shmid_to_user function in ipc/shm.c in the Linux kernel before 2.6.37-rc1 does not initialize a
    certain structure, which allows local users to obtain potentially sensitive information from kernel stack
    memory via vectors related to the shmctl system call and the old shm interface. (CVE-2010-4072)

  - The ipc subsystem in the Linux kernel before 2.6.37-rc1 does not initialize certain structures, which
    allows local users to obtain potentially sensitive information from kernel stack memory via vectors
    related to the (1) compat_sys_semctl, (2) compat_sys_msgctl, and (3) compat_sys_shmctl functions in
    ipc/compat.c; and the (4) compat_sys_mq_open and (5) compat_sys_mq_getsetattr functions in
    ipc/compat_mq.c. (CVE-2010-4073)

  - The USB subsystem in the Linux kernel before 2.6.36-rc5 does not properly initialize certain structure
    members, which allows local users to obtain potentially sensitive information from kernel stack memory via
    vectors related to TIOCGICOUNT ioctl calls, and the (1) mos7720_ioctl function in
    drivers/usb/serial/mos7720.c and (2) mos7840_ioctl function in drivers/usb/serial/mos7840.c.
    (CVE-2010-4074)

  - The uart_get_count function in drivers/serial/serial_core.c in the Linux kernel before 2.6.37-rc1 does not
    properly initialize a certain structure member, which allows local users to obtain potentially sensitive
    information from kernel stack memory via a TIOCGICOUNT ioctl call. (CVE-2010-4075)

  - The ntty_ioctl_tiocgicount function in drivers/char/nozomi.c in the Linux kernel 2.6.36.1 and earlier does
    not properly initialize a certain structure member, which allows local users to obtain potentially
    sensitive information from kernel stack memory via a TIOCGICOUNT ioctl call. (CVE-2010-4077)

  - The ivtvfb_ioctl function in drivers/media/video/ivtv/ivtvfb.c in the Linux kernel before 2.6.36-rc8 does
    not properly initialize a certain structure member, which allows local users to obtain potentially
    sensitive information from kernel stack memory via an FBIOGET_VBLANK ioctl call. (CVE-2010-4079)

  - The snd_hdsp_hwdep_ioctl function in sound/pci/rme9652/hdsp.c in the Linux kernel before 2.6.36-rc6 does
    not initialize a certain structure, which allows local users to obtain potentially sensitive information
    from kernel stack memory via an SNDRV_HDSP_IOCTL_GET_CONFIG_INFO ioctl call. (CVE-2010-4080)

  - The snd_hdspm_hwdep_ioctl function in sound/pci/rme9652/hdspm.c in the Linux kernel before 2.6.36-rc6 does
    not initialize a certain structure, which allows local users to obtain potentially sensitive information
    from kernel stack memory via an SNDRV_HDSPM_IOCTL_GET_CONFIG_INFO ioctl call. (CVE-2010-4081)

  - The viafb_ioctl_get_viafb_info function in drivers/video/via/ioctl.c in the Linux kernel before 2.6.36-rc5
    does not properly initialize a certain structure member, which allows local users to obtain potentially
    sensitive information from kernel stack memory via a VIAFB_GET_INFO ioctl call. (CVE-2010-4082)

  - The copy_semid_to_user function in ipc/sem.c in the Linux kernel before 2.6.36 does not initialize a
    certain structure, which allows local users to obtain potentially sensitive information from kernel stack
    memory via a (1) IPC_INFO, (2) SEM_INFO, (3) IPC_STAT, or (4) SEM_STAT command in a semctl system call.
    (CVE-2010-4083)

  - The sk_run_filter function in net/core/filter.c in the Linux kernel before 2.6.36.2 does not check whether
    a certain memory location has been initialized before executing a (1) BPF_S_LD_MEM or (2) BPF_S_LDX_MEM
    instruction, which allows local users to obtain potentially sensitive information from kernel stack memory
    via a crafted socket filter. (CVE-2010-4158)

  - Multiple integer overflows in the (1) pppol2tp_sendmsg function in net/l2tp/l2tp_ppp.c, and the (2)
    l2tp_ip_sendmsg function in net/l2tp/l2tp_ip.c, in the PPPoL2TP and IPoL2TP implementations in the Linux
    kernel before 2.6.36.2 allow local users to cause a denial of service (heap memory corruption and panic)
    or possibly gain privileges via a crafted sendto call. (CVE-2010-4160)

  - Multiple integer overflows in fs/bio.c in the Linux kernel before 2.6.36.2 allow local users to cause a
    denial of service (system crash) via a crafted device ioctl to a SCSI device. (CVE-2010-4162)

  - The blk_rq_map_user_iov function in block/blk-map.c in the Linux kernel before 2.6.36.2 allows local users
    to cause a denial of service (panic) via a zero-length I/O request in a device ioctl to a SCSI device.
    (CVE-2010-4163)

  - The hci_uart_tty_open function in the HCI UART driver (drivers/bluetooth/hci_ldisc.c) in the Linux kernel
    2.6.36, and possibly other versions, does not verify whether the tty has a write operation, which allows
    local users to cause a denial of service (NULL pointer dereference) via vectors related to the Bluetooth
    driver. (CVE-2010-4242)

  - Race condition in the __exit_signal function in kernel/exit.c in the Linux kernel before 2.6.37-rc2 allows
    local users to cause a denial of service via vectors related to multithreaded exec, the use of a thread
    group leader in kernel/posix-cpu-timers.c, and the selection of a new thread group leader in the de_thread
    function in fs/exec.c. (CVE-2010-4248)

  - The wait_for_unix_gc function in net/unix/garbage.c in the Linux kernel before 2.6.37-rc3-next-20101125
    does not properly select times for garbage collection of inflight sockets, which allows local users to
    cause a denial of service (system hang) via crafted use of the socketpair and sendmsg system calls for
    SOCK_SEQPACKET sockets. (CVE-2010-4249)

  - The igb_receive_skb function in drivers/net/igb/igb_main.c in the Intel Gigabit Ethernet (aka igb)
    subsystem in the Linux kernel before 2.6.34, when Single Root I/O Virtualization (SR-IOV) and promiscuous
    mode are enabled but no VLANs are registered, allows remote attackers to cause a denial of service (NULL
    pointer dereference and panic) and possibly have unspecified other impact via a VLAN tagged frame.
    (CVE-2010-4263)

  - Linux kernel 2.6.33 and 2.6.34.y does not initialize the kvm_vcpu_events->interrupt.pad structure member,
    which allows local users to obtain potentially sensitive information from kernel stack memory via
    unspecified vectors. (CVE-2010-4525)

  - The blk_rq_map_user_iov function in block/blk-map.c in the Linux kernel before 2.6.37-rc7 allows local
    users to cause a denial of service (panic) via a zero-length I/O request in a device ioctl to a SCSI
    device, related to an unaligned map. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2010-4163. (CVE-2010-4668)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0007.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3705");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-71.14.1.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-0007');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-71.14.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-71.14.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-debug / kernel-debug-devel / etc');
}
