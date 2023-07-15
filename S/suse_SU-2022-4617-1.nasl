#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4617-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(169292);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2016-3695",
    "CVE-2020-16119",
    "CVE-2020-36516",
    "CVE-2021-4037",
    "CVE-2021-33135",
    "CVE-2022-1184",
    "CVE-2022-1263",
    "CVE-2022-1882",
    "CVE-2022-2153",
    "CVE-2022-2586",
    "CVE-2022-2588",
    "CVE-2022-2602",
    "CVE-2022-2639",
    "CVE-2022-2663",
    "CVE-2022-2873",
    "CVE-2022-2905",
    "CVE-2022-2938",
    "CVE-2022-2959",
    "CVE-2022-2964",
    "CVE-2022-2977",
    "CVE-2022-2978",
    "CVE-2022-3028",
    "CVE-2022-3078",
    "CVE-2022-3114",
    "CVE-2022-3169",
    "CVE-2022-3176",
    "CVE-2022-3202",
    "CVE-2022-3239",
    "CVE-2022-3303",
    "CVE-2022-3424",
    "CVE-2022-3435",
    "CVE-2022-3521",
    "CVE-2022-3524",
    "CVE-2022-3526",
    "CVE-2022-3535",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3565",
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2022-3577",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-3619",
    "CVE-2022-3621",
    "CVE-2022-3625",
    "CVE-2022-3628",
    "CVE-2022-3629",
    "CVE-2022-3633",
    "CVE-2022-3635",
    "CVE-2022-3640",
    "CVE-2022-3643",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-3707",
    "CVE-2022-3903",
    "CVE-2022-4095",
    "CVE-2022-4129",
    "CVE-2022-4139",
    "CVE-2022-4378",
    "CVE-2022-20368",
    "CVE-2022-20369",
    "CVE-2022-26373",
    "CVE-2022-28356",
    "CVE-2022-28693",
    "CVE-2022-28748",
    "CVE-2022-32250",
    "CVE-2022-32296",
    "CVE-2022-33981",
    "CVE-2022-36879",
    "CVE-2022-36946",
    "CVE-2022-39188",
    "CVE-2022-39189",
    "CVE-2022-39190",
    "CVE-2022-40476",
    "CVE-2022-40768",
    "CVE-2022-41218",
    "CVE-2022-41674",
    "CVE-2022-41848",
    "CVE-2022-41849",
    "CVE-2022-41850",
    "CVE-2022-41858",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2022-42703",
    "CVE-2022-42719",
    "CVE-2022-42720",
    "CVE-2022-42721",
    "CVE-2022-42722",
    "CVE-2022-42895",
    "CVE-2022-42896",
    "CVE-2022-43750",
    "CVE-2022-43945",
    "CVE-2022-45869",
    "CVE-2022-45888",
    "CVE-2022-45934"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4617-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2022:4617-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:4617-1 advisory.

  - The einj_error_inject function in drivers/acpi/apei/einj.c in the Linux kernel allows local users to
    simulate hardware errors and consequently cause a denial of service by leveraging failure to disable APEI
    error injection through EINJ when securelevel is set. (CVE-2016-3695)

  - Use-after-free vulnerability in the Linux kernel exploitable by a local attacker due to reuse of a DCCP
    socket with an attached dccps_hc_tx_ccid object as a listener after being released. Fixed in Ubuntu Linux
    kernel 5.4.0-51.56, 5.3.0-68.63, 4.15.0-121.123, 4.4.0-193.224, 3.13.0.182.191 and 3.2.0-149.196.
    (CVE-2020-16119)

  - An issue was discovered in the Linux kernel through 5.16.11. The mixed IPID assignment method with the
    hash-based IPID assignment policy allows an off-path attacker to inject data into a victim's TCP session
    or terminate that session. (CVE-2020-36516)

  - Uncontrolled resource consumption in the Linux kernel drivers for Intel(R) SGX may allow an authenticated
    user to potentially enable denial of service via local access. (CVE-2021-33135)

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - A NULL pointer dereference issue was found in KVM when releasing a vCPU with dirty ring support enabled.
    This flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a
    kernel oops condition that results in a denial of service. (CVE-2022-1263)

  - A use-after-free flaw was found in the Linux kernel's pipes functionality in how a user performs
    manipulations with the pipe post_one_notification() after free_pipe_info() that is already called. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-1882)

  - Product: AndroidVersions: Android kernelAndroid ID: A-224546354References: Upstream kernel
    (CVE-2022-20368)

  - In v4l2_m2m_querybuf of v4l2-mem2mem.c, there is a possible out of bounds write due to improper input
    validation. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-223375145References: Upstream kernel (CVE-2022-20369)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - kernel: nf_tables cross-table potential use-after-free may lead to local privilege escalation
    (CVE-2022-2586)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

  - A flaw was found in the Linux kernel. The existing KVM SEV API has a vulnerability that allows a non-root
    (host) user-level application to crash the host kernel by creating a confidential guest VM instance in AMD
    CPU that supports Secure Encrypted Virtualization (SEV). (CVE-2022-0171) (CVE-2022-2602)

  - Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow
    an authorized user to potentially enable information disclosure via local access. (CVE-2022-26373)

  - An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of
    actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size()
    function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-2639)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - A flaw was found in hw. Mis-trained branch predictions for return instructions may allow arbitrary
    speculative code execution under certain microarchitecture-dependent conditions. (CVE-2022-23816)
    (CVE-2022-28693)

  - An out-of-bounds memory access flaw was found in the Linux kernel Intel's iSMT SMBus host controller
    driver in the way a user triggers the I2C_SMBUS_BLOCK_DATA (with the ioctl I2C_SMBUS) with malicious input
    data. This flaw allows a local user to crash the system. (CVE-2022-2873)

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - A flaw was found in the Linux kernel's implementation of Pressure Stall Information. While the feature is
    disabled by default, it could allow an attacker to crash the system or have other memory-corruption side
    effects. (CVE-2022-2938)

  - A race condition was found in the Linux kernel's watch queue due to a missing lock in pipe_resize_ring().
    The specific flaw exists within the handling of pipe buffers. The issue results from the lack of proper
    locking when performing operations on an object. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-2959)

  - A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet
    Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.
    (CVE-2022-2964)

  - A flaw was found in the Linux kernel implementation of proxied virtualized TPM devices. On a system where
    virtualized TPM devices are configured (this is not the default) a local attacker can create a use-after-
    free and create a situation where it may be possible to escalate privileges on the system. (CVE-2022-2977)

  - A flaw use after free in the Linux kernel NILFS file system was found in the way user triggers function
    security_inode_alloc to fail with following call to function nilfs_mdt_destroy. A local user could use
    this flaw to crash the system or potentially escalate their privileges on the system. (CVE-2022-2978)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - An issue was discovered in the Linux kernel through 5.16-rc6. There is a lack of check after calling
    vzalloc() and lack of free after allocation in drivers/media/test-drivers/vidtv/vidtv_s302m.c.
    (CVE-2022-3078)

  - An issue was discovered in the Linux kernel through 5.16-rc6. imx_register_uart_clocks in
    drivers/clk/imx/clk.c lacks check of the return value of kcalloc() and will cause the null pointer
    dereference. (CVE-2022-3114)

  - A flaw was found in the Linux kernel. A denial of service flaw may occur if there is a consecutive request
    of the NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
    in a PCIe link disconnect. (CVE-2022-3169)

  - There exists a use-after-free in io_uring in the Linux kernel. Signalfd_poll() and binder_poll() use a
    waitqueue whose lifetime is the current task. It will send a POLLFREE notification to all waiters before
    the queue is freed. Unfortunately, the io_uring poll doesn't handle POLLFREE. This allows a use-after-free
    to occur if a signalfd or binder fd is polled with io_uring poll, and the waitqueue gets freed. We
    recommend upgrading past commit fc78b2fc21f10c4c9c4d5d659a685710ffa63659 (CVE-2022-3176)

  - A NULL pointer dereference flaw in diFree in fs/jfs/inode.c in Journaled File System (JFS)in the Linux
    kernel. This could allow a local attacker to crash the system or leak kernel internal information.
    (CVE-2022-3202)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. This occurs because of use of Algorithm 4 (Double-Hash Port Selection Algorithm) of RFC 6056.
    (CVE-2022-32296)

  - A flaw use after free in the Linux kernel video4linux driver was found in the way user triggers
    em28xx_usb_probe() for the Empia 28xx based TV cards. A local user could use this flaw to crash the system
    or potentially escalate their privileges on the system. (CVE-2022-3239)

  - A race condition flaw was found in the Linux kernel sound subsystem due to improper locking. It could lead
    to a NULL pointer dereference while handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or
    member of the audio group) could use this flaw to crash the system, resulting in a denial of service
    condition (CVE-2022-3303)

  - drivers/block/floppy.c in the Linux kernel before 5.17.6 is vulnerable to a denial of service, because of
    a concurrency use-after-free flaw after deallocating raw_cmd in the raw_cmd_ioctl function.
    (CVE-2022-33981)

  - A use-after-free flaw was found in the Linux kernel's SGI GRU driver in the way the first
    gru_file_unlocked_ioctl function is called by the user, where a fail pass occurs in the
    gru_check_chiplet_assignment function. This flaw allows a local user to crash or potentially escalate
    their privileges on the system. (CVE-2022-3424)

  - A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function kcm_tx_work of the file net/kcm/kcmsock.c of the component kcm. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211018 is the identifier
    assigned to this vulnerability. (CVE-2022-3521)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability classified as problematic was found in Linux Kernel. This vulnerability affects the
    function macvlan_handle_frame of the file drivers/net/macvlan.c of the component skb. The manipulation
    leads to memory leak. The attack can be initiated remotely. It is recommended to apply a patch to fix this
    issue. The identifier of this vulnerability is VDB-211024. (CVE-2022-3526)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

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

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function l2cap_recv_acldata of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211918 is the
    identifier assigned to this vulnerability. (CVE-2022-3619)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_bmap_lookup_at_level of the file fs/nilfs2/inode.c of the component nilfs2. The manipulation leads
    to null pointer dereference. It is possible to launch the attack remotely. It is recommended to apply a
    patch to fix this issue. The identifier of this vulnerability is VDB-211920. (CVE-2022-3621)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - A buffer overflow flaw was found in the Linux kernel Broadcom Full MAC Wi-Fi driver. This issue occurs
    when a user connects to a malicious USB device. This can allow a local user to crash the system or
    escalate their privileges. (CVE-2022-3628)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this
    vulnerability. (CVE-2022-3629)

  - A vulnerability classified as problematic has been found in Linux Kernel. Affected is the function
    j1939_session_destroy of the file net/can/j1939/transport.c. The manipulation leads to memory leak. It is
    recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211932.
    (CVE-2022-3633)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function tst_timer of the file drivers/atm/idt77252.c of the component IPsec. The manipulation
    leads to use after free. It is recommended to apply a patch to fix this issue. VDB-211934 is the
    identifier assigned to this vulnerability. (CVE-2022-3635)

  - A vulnerability, which was classified as critical, was found in Linux Kernel. Affected is the function
    l2cap_conn_del of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads
    to use after free. It is recommended to apply a patch to fix this issue. The identifier of this
    vulnerability is VDB-211944. (CVE-2022-3640)

  - Guests can trigger NIC interface reset/abort/crash via netback It is possible for a guest to trigger a NIC
    interface reset/abort/crash in a Linux based network backend by sending certain kinds of packets. It
    appears to be an (unwritten?) assumption in the rest of the Linux network stack that packet protocol
    headers are all contained within the linear section of the SKB and some NICs behave badly if this is not
    the case. This has been reported to occur with Cisco (enic) and Broadcom NetXtrem II BCM5780 (bnx2x)
    though it may be an issue with other NICs/drivers as well. In case the frontend is sending requests with
    split headers, netback will forward those violating above mentioned assumption to the networking core,
    resulting in said misbehavior. (CVE-2022-3643)

  - A vulnerability, which was classified as problematic, has been found in Linux Kernel. This issue affects
    the function nilfs_attach_log_writer of the file fs/nilfs2/segment.c of the component BPF. The
    manipulation leads to memory leak. The attack may be initiated remotely. It is recommended to apply a
    patch to fix this issue. The identifier VDB-211961 was assigned to this vulnerability. (CVE-2022-3646)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function
    nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211992. (CVE-2022-3649)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

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

  - A null pointer dereference issue was discovered in fs/io_uring.c in the Linux kernel before 5.15.62. A
    local user could use this flaw to crash the system or potentially cause a denial of service.
    (CVE-2022-40476)

  - drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information
    from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.
    (CVE-2022-40768)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - A flaw was found in the Linux kernel's Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing
    sk_user_data can lead to a race condition and NULL pointer dereference. A local user could use this flaw
    to potentially crash the system causing a denial of service. (CVE-2022-4129)

  - An incorrect TLB flush issue was found in the Linux kernel's GPU i915 kernel driver, potentially leading
    to random memory corruption or data leaks. This flaw could allow a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-4139)

  - An issue was discovered in the Linux kernel before 5.19.16. Attackers able to inject WLAN frames could
    cause a buffer overflow in the ieee80211_bss_info_update function in net/mac80211/scan.c. (CVE-2022-41674)

  - drivers/char/pcmcia/synclink_cs.c in the Linux kernel through 5.19.12 has a race condition and resultant
    use-after-free if a physically proximate attacker removes a PCMCIA device while calling ioctl, aka a race
    condition between mgslpc_ioctl and mgslpc_detach. (CVE-2022-41848)

  - drivers/video/fbdev/smscufx.c in the Linux kernel through 5.19.12 has a race condition and resultant use-
    after-free if a physically proximate attacker removes a USB device while calling open(), aka a race
    condition between ufx_ops_open and ufx_usb_disconnect. (CVE-2022-41849)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - A flaw was found in the Linux kernel. A NULL pointer dereference may occur while a slip driver is in
    progress to detach in sl_tx_timeout in drivers/net/slip/slip.c. This issue could allow an attacker to
    crash the system or leak internal kernel information. (CVE-2022-41858)

  - Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced
    another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the
    XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock
    could occur in case of netpoll being active for the interface the xen-netback driver is connected to
    (CVE-2022-42329). (CVE-2022-42328, CVE-2022-42329)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - A use-after-free in the mac80211 stack when parsing a multi-BSSID element in the Linux kernel 5.2 through
    5.19.x before 5.19.16 could be used by attackers (able to inject WLAN frames) to crash the kernel and
    potentially execute code. (CVE-2022-42719)

  - Various refcounting bugs in the multi-BSS handling in the mac80211 stack in the Linux kernel 5.1 through
    5.19.x before 5.19.16 could be used by local attackers (able to inject WLAN frames) to trigger use-after-
    free conditions to potentially execute code. (CVE-2022-42720)

  - A list management bug in BSS handling in the mac80211 stack in the Linux kernel 5.1 through 5.19.x before
    5.19.16 could be used by local attackers (able to inject WLAN frames) to corrupt a linked list and, in
    turn, potentially execute code. (CVE-2022-42721)

  - In the Linux kernel 5.8 through 5.19.x before 5.19.16, local attackers able to inject WLAN frames into the
    mac80211 stack could cause a NULL pointer dereference denial-of-service attack against the beacon
    protection of P2P devices. (CVE-2022-42722)

  - There is an infoleak vulnerability in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_parse_conf_req
    function which can be used to leak kernel pointers remotely. We recommend upgrading past commit
    https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e
    https://www.google.com/url (CVE-2022-42895)

  - There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect
    and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively)
    remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within
    proximity of the victim. We recommend upgrading past commit https://www.google.com/url
    https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4
    https://www.google.com/url (CVE-2022-42896)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in how a user changes certain
    kernel parameters and variables. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2022-4378)

  - The Linux kernel NFSD implementation prior to versions 5.19.17 and 6.0.2 are vulnerable to buffer
    overflow. NFSD tracks the number of pages held by each NFSD thread by combining the receive and send
    buffers of a remote procedure call (RPC) into a single array of pages. A client can force the send buffer
    to shrink by sending an RPC message over TCP with garbage data added at the end of the message. The RPC
    message with garbage data is still correctly formed according to the specification and is passed forward
    to handlers. Vulnerable code in NFSD is not expecting the oversized request and writes beyond the
    allocated buffer space. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H (CVE-2022-43945)

  - A race condition in the x86 KVM subsystem in the Linux kernel through 6.1-rc6 allows guest OS users to
    cause a denial of service (host OS crash or host OS memory corruption) when nested virtualisation and the
    TDP MMU are enabled. (CVE-2022-45869)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/char/xillybus/xillyusb.c has a race
    condition and use-after-free during physical removal of a USB device. (CVE-2022-45888)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1023051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1032323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204228");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206391");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-December/013342.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?808b8b8c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-3695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1263");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39190");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42328");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42329");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-42896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-43945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45934");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32250");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3643");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_15_5-rt");
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
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-rt-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-rt-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-rt-5.14.21-150400.15.5.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-devel-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-rt-5.14.21-150400.15.5.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-rt-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150400.15.5.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_15_5-rt-1-150400.1.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
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
