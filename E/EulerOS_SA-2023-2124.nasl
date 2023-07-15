#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176821);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/07");

  script_cve_id(
    "CVE-2022-2196",
    "CVE-2022-2602",
    "CVE-2022-3111",
    "CVE-2022-3114",
    "CVE-2022-3239",
    "CVE-2022-3303",
    "CVE-2022-3424",
    "CVE-2022-3435",
    "CVE-2022-3523",
    "CVE-2022-3524",
    "CVE-2022-3534",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2022-3577",
    "CVE-2022-3586",
    "CVE-2022-3606",
    "CVE-2022-3623",
    "CVE-2022-3625",
    "CVE-2022-3629",
    "CVE-2022-3707",
    "CVE-2022-3903",
    "CVE-2022-4129",
    "CVE-2022-4269",
    "CVE-2022-4378",
    "CVE-2022-4662",
    "CVE-2022-4696",
    "CVE-2022-20409",
    "CVE-2022-20422",
    "CVE-2022-20423",
    "CVE-2022-20568",
    "CVE-2022-20572",
    "CVE-2022-27672",
    "CVE-2022-39188",
    "CVE-2022-39189",
    "CVE-2022-39190",
    "CVE-2022-41218",
    "CVE-2022-41850",
    "CVE-2022-42703",
    "CVE-2022-43750",
    "CVE-2022-47929",
    "CVE-2022-47946",
    "CVE-2023-0045",
    "CVE-2023-0179",
    "CVE-2023-0240",
    "CVE-2023-0394",
    "CVE-2023-0461",
    "CVE-2023-0590",
    "CVE-2023-0597",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1095",
    "CVE-2023-1118",
    "CVE-2023-1382",
    "CVE-2023-20928",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-23586",
    "CVE-2023-26545",
    "CVE-2023-28327",
    "CVE-2023-28328"
  );

  script_name(english:"EulerOS Virtualization 2.11.0 : kernel (EulerOS-SA-2023-2124)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - In io_identity_cow of io_uring.c, there is a possible way to corrupt memory due to a use after free. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238177383References:
    Upstream kernel (CVE-2022-20409)

  - In emulation_proc_handler of armv8_deprecated.c, there is a possible way to corrupt memory due to a race
    condition. This could lead to local escalation of privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid
    ID: A-237540956References: Upstream kernel (CVE-2022-20422)

  - In rndis_set_response of rndis.c, there is a possible out of bounds write due to an integer overflow. This
    could lead to local escalation of privilege if a malicious USB device is attached with no additional
    execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions:
    Android kernelAndroid ID: A-239842288References: Upstream kernel (CVE-2022-20423)

  - In (TBD) of (TBD), there is a possible way to corrupt kernel memory due to a use after free. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-220738351References:
    Upstream kernel (CVE-2022-20568)

  - In verity_target of dm-verity-target.c, there is a possible way to modify read-only files due to a missing
    permission check. This could lead to local escalation of privilege with System execution privileges
    needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid
    ID: A-234475629References: Upstream kernel (CVE-2022-20572)

  - A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

  - When SMT is enabled, certain AMD processors may speculatively execute instructions using a target from the
    sibling thread after an SMT mode switch potentially resulting in information disclosure. (CVE-2022-27672)

  - An issue was discovered in the Linux kernel through 5.16-rc6. free_charger_irq() in
    drivers/power/supply/wm8350_power.c lacks free of WM8350_IRQ_CHG_FAST_RDY, which is registered in
    wm8350_init_charger(). (CVE-2022-3111)

  - An issue was discovered in the Linux kernel through 5.16-rc6. imx_register_uart_clocks in
    drivers/clk/imx/clk.c lacks check of the return value of kcalloc() and will cause the null pointer
    dereference. (CVE-2022-3114)

  - A flaw use after free in the Linux kernel video4linux driver was found in the way user triggers
    em28xx_usb_probe() for the Empia 28xx based TV cards. A local user could use this flaw to crash the system
    or potentially escalate their privileges on the system. (CVE-2022-3239)

  - A race condition flaw was found in the Linux kernel sound subsystem due to improper locking. It could lead
    to a NULL pointer dereference while handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or
    member of the audio group) could use this flaw to crash the system, resulting in a denial of service
    condition (CVE-2022-3303)

  - A use-after-free flaw was found in the Linux kernel's SGI GRU driver in the way the first
    gru_file_unlocked_ioctl function is called by the user, where a fail pass occurs in the
    gru_check_chiplet_assignment function. This flaw allows a local user to crash or potentially escalate
    their privileges on the system. (CVE-2022-3424)

  - A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is an unknown
    function of the file mm/memory.c of the component Driver Handler. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211020. (CVE-2022-3523)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability classified as critical has been found in Linux Kernel. Affected is the function
    btf_dump_name_dups of the file tools/lib/bpf/btf_dump.c of the component libbpf. The manipulation leads to
    use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability
    is VDB-211032. (CVE-2022-3534)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function
    tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It
    is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this
    vulnerability. (CVE-2022-3566)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier
    assigned to this vulnerability. (CVE-2022-3567)

  - An out-of-bounds memory write flaw was found in the Linux kernel's Kid-friendly Wired Controller driver.
    This flaw allows a local user to crash or potentially escalate their privileges on the system. It is in
    bigben_probe of drivers/hid/hid-bigbenff.c. The reason is incorrect assumption - bigben devices all have
    inputs. However, malicious devices can break this assumption, leaking to out-of-bound write.
    (CVE-2022-3577)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. This affects the
    function find_prog_by_sec_insn of the file tools/lib/bpf/libbpf.c of the component BPF. The manipulation
    leads to null pointer dereference. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211749 was assigned to this vulnerability. (CVE-2022-3606)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this
    vulnerability. (CVE-2022-3629)

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - An incorrect read request flaw was found in the Infrared Transceiver USB driver in the Linux kernel. This
    issue occurs when a user attaches a malicious USB device. A local user could use this flaw to starve the
    resources, causing denial of service or potentially crashing the system. (CVE-2022-3903)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - An issue was discovered the x86 KVM subsystem in the Linux kernel before 5.18.17. Unprivileged guest users
    can compromise the guest kernel because TLB flush operations are mishandled in certain KVM_VCPU_PREEMPTED
    situations. (CVE-2022-39189)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action 'mirred') a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in how a user changes certain
    kernel parameters and variables. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2022-4378)

  - A flaw incorrect access control in the Linux kernel USB core subsystem was found in the way user attaches
    usb device. A local user could use this flaw to crash the system. (CVE-2022-4662)

  - There exists a use-after-free vulnerability in the Linux kernel through io_uring and the IORING_OP_SPLICE
    operation. If IORING_OP_SPLICE is missing the IO_WQ_WORK_FILES flag, which signals that the operation
    won't use current->nsproxy, so its reference counter is not increased. This assumption is not always true
    as calling io_splice on specific files will call the get_uts function which will use current->nsproxy
    leading to invalidly decreasing its reference counter later causing the use-after-free vulnerability. We
    recommend upgrading to version 5.10.160 or above (CVE-2022-4696)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with 'tc qdisc' and 'tc class' commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - An issue was discovered in the Linux kernel 5.10.x before 5.10.155. A use-after-free in io_sqpoll_wait_sq
    in fs/io_uring.c allows an attacker to crash the kernel, resulting in denial of service. finish_wait can
    be skipped. An attack can occur in some situations by forking a process and then quickly terminating it.
    NOTE: later kernel versions, such as the 5.15 longterm series, substantially changed the implementation of
    io_sqpoll_wait_sq. (CVE-2022-47946)

  - The current implementation of the prctl syscall does not issue an IBPB immediately during the syscall. The
    ib_prctl_set function updates the Thread Information Flags (TIFs) for the task and updates the SPEC_CTRL
    MSR on the function __speculation_ctrl_update, but the IBPB is only issued on the next schedule, when the
    TIF bits are checked. This leaves the victim vulnerable to values already injected on the BTB, prior to
    the prctl syscall. The patch that added the support for the conditional mitigation via prctl
    (ib_prctl_set) dates back to the kernel 4.9.176. We recommend upgrading past commit
    a664ec9158eeddd75121d39c9a0758016097fa96 (CVE-2023-0045)

  - A buffer overflow vulnerability was found in the Netfilter subsystem in the Linux Kernel. This issue could
    allow the leakage of both stack and heap addresses, and potentially allow Local Privilege Escalation to
    the root user via arbitrary code execution. (CVE-2023-0179)

  - There is a logic error in io_uring's implementation which can be used to trigger a use-after-free
    vulnerability leading to privilege escalation. In the io_prep_async_work function the assumption that the
    last io_grab_identity call cannot return false is not true, and in this case the function will use the
    init_cred or the previous linked requests identity to do operations instead of using the current identity.
    This can lead to reference counting issues causing use-after-free. We recommend upgrading past version
    5.10.161. (CVE-2023-0240)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A use-after-free flaw was found in qdisc_graft in net/sched/sch_api.c in the Linux Kernel due to a race
    problem. This flaw leads to a denial of service issue. If patch ebda44da44f6 ('net: sched: fix race
    condition in qdisc_graft()') not applied yet, then kernel could be affected. (CVE-2023-0590)

  - A flaw possibility of memory leak in the Linux kernel cpu_entry_area mapping of X86 CPU data to memory was
    found in the way user can guess location of exception stack(s) or other important data. A local user could
    use this flaw to get access to some important data with expected location in memory. (CVE-2023-0597)

  - A memory corruption flaw was found in the Linux kernel's human interface device (HID) subsystem in how a
    user inserts a malicious USB device. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2023-1073)

  - A memory leak flaw was found in the Linux kernel's Stream Control Transmission Protocol. This issue may
    occur when a user starts a malicious networking service and someone connects to this service. This could
    allow a local user to starve resources, causing a denial of service. (CVE-2023-1074)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the
    transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list
    -- the list head is all zeroes, this results in a NULL pointer dereference. (CVE-2023-1095)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - A data race flaw was found in the Linux kernel, between where con is allocated and con->sock is set. This
    issue leads to a NULL pointer dereference when accessing con->sock->sk in net/tipc/topsrv.c in the tipc
    protocol in the Linux kernel. (CVE-2023-1382)

  - In binder_vma_close of binder.c, there is a possible use after free due to improper locking. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-254837884References:
    Upstream kernel (CVE-2023-20928)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - Due to a vulnerability in the io_uring subsystem, it is possible to leak kernel memory information to the
    user process. timens_install calls current_is_single_threaded to determine if the current process is
    single-threaded, but this call does not consider io_uring's io_worker threads, thus it is possible to
    insert a time namespace's vvar page to process's memory space via a page fault. When this time namespace
    is destroyed, the vvar page is also freed, but not removed from the process' memory, and a next page
    allocated by the kernel will be still available from the user-space process and can leak memory contents
    via this (read-only) use-after-free vulnerability. We recommend upgrading past version 5.10.161 or commit
    788d0824269bef539fe31a785b1517882eafed93
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/io_uring (CVE-2023-23586)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - A NULL pointer dereference flaw was found in the UNIX protocol in net/unix/diag.c In unix_diag_get_exact
    in the Linux Kernel. The newly allocated skb does not have sk, leading to a NULL pointer. This flaw allows
    a local user to crash or potentially cause a denial of service. (CVE-2023-28327)

  - A NULL pointer dereference flaw was found in the az6027 driver in drivers/media/usb/dev-usb/az6027.c in
    the Linux Kernel. The message from user space is not checked properly before transferring into the device.
    This flaw allows a local user to crash the system or potentially cause a denial of service.
    (CVE-2023-28328)

  - A flaw was found in hw. Mis-trained branch predictions for return instructions may allow arbitrary
    speculative code execution under certain microarchitecture-dependent conditions. (CVE-2022-23816)
    (CVE-2022-2602)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df630306");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.11.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h815.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h815.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
