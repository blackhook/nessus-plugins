#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2193.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143542);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2018-20669", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-27777", "CVE-2020-28974", "CVE-2020-29371", "CVE-2020-4788");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-2193)");
  script_summary(english:"Check for the openSUSE-2020-2193 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-29371: An issue was discovered in
    romfs_dev_read in fs/romfs/storage.c where uninitialized
    memory leaks to userspace, aka CID-bcf85fcedfdd
    (bnc#1179429).

  - CVE-2020-15436: Use-after-free vulnerability in
    fs/block_dev.c allowed local users to gain privileges or
    cause a denial of service by leveraging improper access
    to a certain error field (bnc#1179141).

  - CVE-2020-4788: IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1)
    processors could allow a local user to obtain sensitive
    information from the data in the L1 cache under
    extenuating circumstances. IBM X-Force ID: 189296
    (bnc#1177666).

  - CVE-2018-20669: An issue where a provided address with
    access_ok() is not checked was discovered in
    i915_gem_execbuffer2_ioctl in
    drivers/gpu/drm/i915/i915_gem_execbuffer.c, where a
    local attacker can craft a malicious IOCTL function call
    to overwrite arbitrary kernel memory, resulting in a
    Denial of Service or privilege escalation (bnc#1122971).

  - CVE-2020-15437: The Linux kernel was vulnerable to a
    NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init_
    ports() that allowed local users to cause a denial of
    service by using the p->serial_in pointer which
    uninitialized (bnc#1179140).

  - CVE-2020-27777: Restrict RTAS requests from userspace
    (CVE-2020-27777 bsc#1179107).

  - CVE-2020-28974: A slab-out-of-bounds read in fbcon could
    be used by local attackers to read privileged
    information or potentially crash the kernel, aka
    CID-3c4e0dff2095. This occurs because KD_FONT_OP_COPY in
    drivers/tty/vt/vt.c can be used for manipulations such
    as font height (bnc#1178589).

The following non-security bugs were fixed :

  - ACPI: GED: fix -Wformat (git-fixes).

  - ALSA: ctl: fix error path at adding user-defined element
    set (git-fixes).

  - ALSA: firewire: Clean up a locking issue in
    copy_resp_to_buf() (git-fixes).

  - ALSA: mixart: Fix mutex deadlock (git-fixes).

  - ASoC: qcom: lpass-platform: Fix memory leak (git-fixes).

  - Bluetooth: btusb: Fix and detect most of the Chinese
    Bluetooth controllers (git-fixes).

  - Bluetooth: hci_bcm: fix freeing not-requested IRQ
    (git-fixes).

  - Convert trailing spaces and periods in path components
    (bsc#1179424).

  - Drivers: hv: vmbus: Remove the unused 'tsc_page' from
    struct hv_context (git-fixes).

  - IB/cma: Fix ports memory leak in cma_configfs
    (bsc#1111666)

  - IB/core: Set qp->real_qp before it may be accessed
    (bsc#1111666)

  - IB/hfi1, qib: Ensure RCU is locked when accessing list
    (bsc#1111666)

  - IB/hfi1: Add RcvShortLengthErrCnt to hfi1stats
    (bsc#1111666)

  - IB/hfi1: Add missing INVALIDATE opcodes for trace
    (bsc#1111666)

  - IB/hfi1: Add software counter for ctxt0 seq drop
    (bsc#1111666)

  - IB/hfi1: Avoid hardlockup with flushlist_lock
    (bsc#1111666)

  - IB/hfi1: Call kobject_put() when kobject_init_and_add()
    fails (bsc#1111666)

  - IB/hfi1: Check for error on call to alloc_rsm_map_table
    (bsc#1111666)

  - IB/hfi1: Close PSM sdma_progress sleep window
    (bsc#1111666)

  - IB/hfi1: Define variables as unsigned long to fix KASAN
    warning (bsc#1111666)

  - IB/hfi1: Ensure full Gen3 speed in a Gen4 system
    (bsc#1111666)

  - IB/hfi1: Fix Spectre v1 vulnerability (bsc#1111666)

  - IB/hfi1: Fix memory leaks in sysfs registration and
    unregistration (bsc#1111666)

  - IB/hfi1: Handle port down properly in pio (bsc#1111666)

  - IB/hfi1: Handle wakeup of orphaned QPs for pio
    (bsc#1111666)

  - IB/hfi1: Insure freeze_work work_struct is canceled on
    shutdown (bsc#1111666)

  - IB/hfi1: Remove unused define (bsc#1111666)

  - IB/hfi1: Silence txreq allocation warnings (bsc#1111666)

  - IB/hfi1: Validate page aligned for a given virtual
    address (bsc#1111666)

  - IB/hfi1: Wakeup QPs orphaned on wait list after flush
    (bsc#1111666)

  - IB/ipoib: Fix double free of skb in case of multicast
    traffic in CM mode (bsc#1111666)

  - IB/ipoib: Fix for use-after-free in ipoib_cm_tx_start
    (bsc#1111666)

  - IB/ipoib: drop useless LIST_HEAD (bsc#1111666)

  - IB/iser: Fix dma_nents type definition (bsc#1111666)

  - IB/iser: Pass the correct number of entries for dma
    mapped SGL (bsc#1111666)

  - IB/mad: Fix use-after-free in ib mad completion handling
    (bsc#1111666)

  - IB/mlx4: Add and improve logging (bsc#1111666)

  - IB/mlx4: Add support for MRA (bsc#1111666)

  - IB/mlx4: Adjust delayed work when a dup is observed
    (bsc#1111666)

  - IB/mlx4: Fix leak in id_map_find_del (bsc#1111666)

  - IB/mlx4: Fix memory leak in add_gid error flow
    (bsc#1111666)

  - IB/mlx4: Fix race condition between catas error reset
    and aliasguid flows (bsc#1111666)

  - IB/mlx4: Fix starvation in paravirt mux/demux
    (bsc#1111666)

  - IB/mlx4: Follow mirror sequence of device add during
    device removal (bsc#1111666)

  - IB/mlx4: Remove unneeded NULL check (bsc#1111666)

  - IB/mlx4: Test return value of calls to
    ib_get_cached_pkey (bsc#1111666)

  - IB/mlx5: Add missing XRC options to QP optional params
    mask (bsc#1111666)

  - IB/mlx5: Compare only index part of a memory window rkey
    (bsc#1111666)

  - IB/mlx5: Do not override existing ip_protocol
    (bsc#1111666)

  - IB/mlx5: Fix RSS Toeplitz setup to be aligned with the
    HW specification (bsc#1111666)

  - IB/mlx5: Fix clean_mr() to work in the expected order
    (bsc#1111666)

  - IB/mlx5: Fix implicit MR release flow (bsc#1111666)

  - IB/mlx5: Fix outstanding_pi index for GSI qps
    (bsc#1111666)

  - IB/mlx5: Fix unreg_umr to ignore the mkey state
    (bsc#1111666)

  - IB/mlx5: Improve ODP debugging messages (bsc#1111666)

  - IB/mlx5: Move MRs to a kernel PD when freeing them to
    the MR cache (bsc#1111666)

  - IB/mlx5: Prevent concurrent MR updates during
    invalidation (bsc#1111666)

  - IB/mlx5: Reset access mask when looping inside page
    fault handler (bsc#1111666)

  - IB/mlx5: Set correct write permissions for implicit ODP
    MR (bsc#1111666)

  - IB/mlx5: Use direct mkey destroy command upon UMR unreg
    failure (bsc#1111666)

  - IB/mlx5: Use fragmented QP's buffer for in-kernel users
    (bsc#1111666)

  - IB/mlx5: WQE dump jumps over first 16 bytes
    (bsc#1111666)

  - IB/mthca: fix return value of error branch in
    mthca_init_cq() (bsc#1111666)

  - IB/qib: Call kobject_put() when kobject_init_and_add()
    fails (bsc#1111666)

  - IB/qib: Fix an error code in qib_sdma_verbs_send()
    (bsc#1111666)

  - IB/qib: Remove a set-but-not-used variable (bsc#1111666)

  - IB/rdmavt: Convert timers to use timer_setup()
    (bsc#1111666)

  - IB/rdmavt: Fix alloc_qpn() WARN_ON() (bsc#1111666)

  - IB/rdmavt: Fix sizeof mismatch (bsc#1111666)

  - IB/rdmavt: Reset all QPs when the device is shut down
    (bsc#1111666)

  - IB/rxe: Fix incorrect cache cleanup in error flow
    (bsc#1111666)

  - IB/rxe: Make counters thread safe (bsc#1111666)

  - IB/srpt: Fix memory leak in srpt_add_one (bsc#1111666)

  - IB/umad: Avoid additional device reference during
    open()/close() (bsc#1111666)

  - IB/umad: Avoid destroying device while it is accessed
    (bsc#1111666)

  - IB/umad: Do not check status of nonseekable_open()
    (bsc#1111666)

  - IB/umad: Fix kernel crash while unloading ib_umad
    (bsc#1111666)

  - IB/umad: Refactor code to use cdev_device_add()
    (bsc#1111666)

  - IB/umad: Simplify and avoid dynamic allocation of class
    (bsc#1111666)

  - IB/usnic: Fix out of bounds index check in query pkey
    (bsc#1111666)

  - IB/uverbs: Fix OOPs upon device disassociation
    (bsc#1111666)

  - IB/(hfi1, qib): Fix WC.byte_len calculation for
    UD_SEND_WITH_IMM (bsc#1111666)

  - IB/(qib, hfi1, rdmavt): Correct ibv_devinfo max_mr value
    (bsc#1111666)

  - KVM host: kabi fixes for psci_version (bsc#1174726).

  - KVM: arm64: Add missing #include of <linux/string.h> in
    guest.c (bsc#1174726).

  - KVM: arm64: Factor out core register ID enumeration
    (bsc#1174726).

  - KVM: arm64: Filter out invalid core register IDs in
    KVM_GET_REG_LIST (bsc#1174726).

  - KVM: arm64: Refactor kvm_arm_num_regs() for easier
    maintenance (bsc#1174726).

  - KVM: arm64: Reject ioctl access to FPSIMD V-regs on SVE
    vcpus (bsc#1174726).

  - NFS: mark nfsiod as CPU_INTENSIVE (bsc#1177304).

  - NFS: only invalidate dentrys that are clearly invalid
    (bsc#1178669 bsc#1170139).

  - PCI: pci-hyperv: Fix build errors on non-SYSFS config
    (git-fixes).

  - RDMA/bnxt_re: Fix Send Work Entry state check while
    polling completions (bsc#1111666)

  - RDMA/bnxt_re: Fix lifetimes in bnxt_re_task
    (bsc#1111666)

  - RDMA/bnxt_re: Fix sizeof mismatch for allocation of
    pbl_tbl. (bsc#1111666)

  - RDMA/bnxt_re: Fix stack-out-of-bounds in
    bnxt_qplib_rcfw_send_message (bsc#1111666)

  - RDMA/cm: Add missing locking around id.state in
    cm_dup_req_handler (bsc#1111666)

  - RDMA/cm: Fix checking for allowed duplicate listens
    (bsc#1111666)

  - RDMA/cm: Remove a race freeing timewait_info
    (bsc#1111666)

  - RDMA/cm: Update num_paths in cma_resolve_iboe_route
    error flow (bsc#1111666)

  - RDMA/cma: Fix false error message (bsc#1111666)

  - RDMA/cma: Protect bind_list and listen_list while
    finding matching cm id (bsc#1111666)

  - RDMA/cma: add missed unregister_pernet_subsys in init
    failure (bsc#1111666)

  - RDMA/cma: fix null-ptr-deref Read in cma_cleanup
    (bsc#1111666)

  - RDMA/core: Do not depend device ODP capabilities on
    kconfig option (bsc#1111666)

  - RDMA/core: Fix invalid memory access in spec_filter_size
    (bsc#1111666)

  - RDMA/core: Fix locking in ib_uverbs_event_read
    (bsc#1111666)

  - RDMA/core: Fix protection fault in ib_mr_pool_destroy
    (bsc#1111666)

  - RDMA/core: Fix race between destroy and release FD
    object (bsc#1111666)

  - RDMA/core: Fix race when resolving IP address
    (bsc#1111666)

  - RDMA/core: Prevent mixed use of FDs between shared
    ufiles (bsc#1111666)

  - RDMA/cxgb3: Delete and properly mark unimplemented
    resize CQ function (bsc#1111666)

  - RDMA/hns: Correct the value of HNS_ROCE_HEM_CHUNK_LEN
    (bsc#1111666)

  - RDMA/hns: Correct typo of hns_roce_create_cq()
    (bsc#1111666)

  - RDMA/hns: Remove unsupported modify_port callback
    (bsc#1111666)

  - RDMA/hns: Set the unsupported wr opcode (bsc#1111666)

  - RDMA/i40iw: Set queue pair state when being queried
    (bsc#1111666)

  - RDMA/i40iw: fix a potential NULL pointer dereference
    (bsc#1111666)

  - RDMA/ipoib: Fix ABBA deadlock with ipoib_reap_ah()
    (bsc#1111666)

  - RDMA/ipoib: Remove check for ETH_SS_TEST (bsc#1111666)

  - RDMA/ipoib: Return void from ipoib_ib_dev_stop()
    (bsc#1111666)

  - RDMA/ipoib: Set rtnl_link_ops for ipoib interfaces
    (bsc#1111666)

  - RDMA/iw_cxgb4: Avoid freeing skb twice in arp failure
    case (bsc#1111666)

  - RDMA/iw_cxgb4: Fix the unchecked ep dereference
    (bsc#1111666)

  - RDMA/iwcm: Fix a lock inversion issue (bsc#1111666)

  - RDMA/iwcm: Fix iwcm work deallocation (bsc#1111666)

  - RDMA/iwcm: move iw_rem_ref() calls out of spinlock
    (bsc#1111666)

  - RDMA/mad: Fix possible memory leak in
    ib_mad_post_receive_mads() (bsc#1111666)

  - RDMA/mlx4: Initialize ib_spec on the stack (bsc#1111666)

  - RDMA/mlx4: Read pkey table length instead of hardcoded
    value (bsc#1111666)

  - RDMA/mlx5: Clear old rate limit when closing QP
    (bsc#1111666)

  - RDMA/mlx5: Delete unreachable handle_atomic code by
    simplifying SW completion (bsc#1111666)

  - RDMA/mlx5: Fix a race with mlx5_ib_update_xlt on an
    implicit MR (bsc#1111666)

  - RDMA/mlx5: Fix access to wrong pointer while performing
    flush due to error (bsc#1111666)

  - RDMA/mlx5: Fix function name typo 'fileds' -> 'fields'
    (bsc#1111666)

  - RDMA/mlx5: Return proper error value (bsc#1111666)

  - RDMA/mlx5: Set GRH fields in query QP on RoCE
    (bsc#1111666)

  - RDMA/mlx5: Verify that QP is created with RQ or SQ
    (bsc#1111666)

  - RDMA/nes: Remove second wait queue initialization call
    (bsc#1111666)

  - RDMA/netlink: Do not always generate an ACK for some
    netlink operations (bsc#1111666)

  - RDMA/ocrdma: Fix out of bounds index check in query pkey
    (bsc#1111666)

  - RDMA/ocrdma: Remove unsupported modify_port callback
    (bsc#1111666)

  - RDMA/pvrdma: Fix missing pci disable in
    pvrdma_pci_probe() (bsc#1111666)

  - RDMA/qedr: Endianness warnings cleanup (bsc#1111666)

  - RDMA/qedr: Fix KASAN: use-after-free in
    ucma_event_handler+0x532 (bsc#1050545).

  - RDMA/qedr: Fix doorbell setting (bsc#1111666)

  - RDMA/qedr: Fix memory leak in iWARP CM (bsc#1050545 ).

  - RDMA/qedr: Fix memory leak in user qp and mr
    (bsc#1111666)

  - RDMA/qedr: Fix reported firmware version (bsc#1111666)

  - RDMA/qedr: Fix use of uninitialized field (bsc#1111666)

  - RDMA/qedr: Remove unsupported modify_port callback
    (bsc#1111666)

  - RDMA/qedr: SRQ's bug fixes (bsc#1111666)

  - RDMA/qib: Delete extra line (bsc#1111666)

  - RDMA/qib: Remove all occurrences of BUG_ON()
    (bsc#1111666)

  - RDMA/qib: Validate ->show()/store() callbacks before
    calling them (bsc#1111666)

  - RDMA/rxe: Drop pointless checks in rxe_init_ports
    (bsc#1111666)

  - RDMA/rxe: Fill in wc byte_len with
    IB_WC_RECV_RDMA_WITH_IMM (bsc#1111666)

  - RDMA/rxe: Fix configuration of atomic queue pair
    attributes (bsc#1111666)

  - RDMA/rxe: Fix memleak in rxe_mem_init_user (bsc#1111666)

  - RDMA/rxe: Fix slab-out-bounds access which lead to
    kernel crash later (bsc#1111666)

  - RDMA/rxe: Fix soft lockup problem due to using tasklets
    in softirq (bsc#1111666)

  - RDMA/rxe: Fix the parent sysfs read when the interface
    has 15 chars (bsc#1111666)

  - RDMA/rxe: Prevent access to wr->next ptr afrer wr is
    posted to send queue (bsc#1111666)

  - RDMA/rxe: Remove unused rxe_mem_map_pages (bsc#1111666)

  - RDMA/rxe: Remove useless rxe_init_device_param
    assignments (bsc#1111666)

  - RDMA/rxe: Return void from rxe_init_port_param()
    (bsc#1111666)

  - RDMA/rxe: Return void from rxe_mem_init_dma()
    (bsc#1111666)

  - RDMA/rxe: Set default vendor ID (bsc#1111666)

  - RDMA/rxe: Set sys_image_guid to be aligned with HW IB
    devices (bsc#1111666)

  - RDMA/rxe: Skip dgid check in loopback mode (bsc#1111666)

  - RDMA/rxe: Use for_each_sg_page iterator on umem SGL
    (bsc#1111666)

  - RDMA/srp: Rework SCSI device reset handling
    (bsc#1111666)

  - RDMA/srpt: Fix typo in srpt_unregister_mad_agent
    docstring (bsc#1111666)

  - RDMA/srpt: Report the SCSI residual to the initiator
    (bsc#1111666)

  - RDMA/ucma: Add missing locking around
    rdma_leave_multicast() (bsc#1111666)

  - RDMA/ucma: Put a lock around every call to the rdma_cm
    layer (bsc#1111666)

  - RDMA/uverbs: Make the event_queue fds return POLLERR
    when disassociated (bsc#1111666)

  - RDMA/vmw_pvrdma: Fix memory leak on pvrdma_pci_remove
    (bsc#1111666)

  - RDMA/vmw_pvrdma: Use atomic memory allocation in create
    AH (bsc#1111666)

  - RDMA: Directly cast the sockaddr union to sockaddr
    (bsc#1111666)

  - RMDA/cm: Fix missing ib_cm_destroy_id() in
    ib_cm_insert_listen() (bsc#1111666)

  - Revert 'kernel/reboot.c: convert simple_strtoul to
    kstrtoint' (bsc#1179418).

  - SUNRPC: fix copying of multiple pages in
    gss_read_proxy_verf() (bsc#1103992).

  - Staging: rtl8188eu: rtw_mlme: Fix uninitialized variable
    authmode (git-fixes).

  - USB: core: Fix regression in Hercules audio card
    (git-fixes).

  - Update references in
    patches.suse/net-smc-tolerate-future-smcd-versions
    (bsc#1172542 LTC#186070 git-fixes).

  - arm/arm64: KVM: Add PSCI version selection API
    (bsc#1174726).

  - arm64: KVM: Fix system register enumeration
    (bsc#1174726).

  - ath10k: Acquire tx_lock in tx error paths (git-fixes).

  - batman-adv: set .owner to THIS_MODULE (git-fixes).

  - bnxt_en: Fix race when modifying pause settings
    (bsc#1050242 ).

  - bnxt_en: Protect bnxt_set_eee() and
    bnxt_set_pauseparam() with mutex (bsc#1050242).

  - btrfs: account ticket size at add/delete time
    (bsc#1178897).

  - btrfs: add helper to obtain number of devices with
    ongoing dev-replace (bsc#1178897).

  - btrfs: check rw_devices, not num_devices for balance
    (bsc#1178897).

  - btrfs: do not delete mismatched root refs (bsc#1178962).

  - btrfs: fix btrfs_calc_reclaim_metadata_size calculation
    (bsc#1178897).

  - btrfs: fix force usage in inc_block_group_ro
    (bsc#1178897).

  - btrfs: fix invalid removal of root ref (bsc#1178962).

  - btrfs: fix reclaim counter leak of space_info objects
    (bsc#1178897).

  - btrfs: fix reclaim_size counter leak after stealing from
    global reserve (bsc#1178897).

  - btrfs: kill min_allocable_bytes in inc_block_group_ro
    (bsc#1178897).

  - btrfs: rework arguments of btrfs_unlink_subvol
    (bsc#1178962).

  - btrfs: split dev-replace locking helpers for read and
    write (bsc#1178897). Needed as a prep patch for further
    improvements around btrfs.

  - can: gs_usb: fix endianess problem with candleLight
    firmware (git-fixes).

  - can: m_can: fix nominal bitiming tseg2 min for version
    >= 3.1 (git-fixes).

  - ceph: add check_session_state() helper and make it
    global (bsc#1179259).

  - ceph: check session state after bumping session->s_seq
    (bsc#1179259).

  - ceph: fix race in concurrent __ceph_remove_cap
    invocations (bsc#1178635).

  - cifs: Fix incomplete memory allocation on setxattr path
    (bsc#1179211).

  - cifs: Return the error from crypt_message when enc/dec
    key not found (bsc#1179426).

  - cifs: remove bogus debug code (bsc#1179427).

  - cxgb4: Fix offset when clearing filter byte counters
    (bsc#1064802 bsc#1066129).

  - docs: ABI: stable: remove a duplicated documentation
    (git-fixes).

  - drm/i915/gvt: Set ENHANCED_FRAME_CAP bit (git-fixes).

  - drm/sun4i: dw-hdmi: fix error return code in
    sun8i_dw_hdmi_bind() (git-fixes).

  - efi/efivars: Add missing kobject_put() in sysfs entry
    creation error path (git-fixes).

  - efi/esrt: Fix reference count leak in
    esre_create_sysfs_entry (git-fixes).

  - efi/x86: Do not panic or BUG() on non-critical error
    conditions (git-fixes).

  - efi/x86: Free efi_pgd with free_pages() (bsc#1112178).

  - efi/x86: Ignore the memory attributes table on i386
    (git-fixes).

  - efi/x86: Map the entire EFI vendor string before copying
    it (git-fixes).

  - efi: cper: Fix possible out-of-bounds access
    (git-fixes).

  - efi: provide empty efi_enter_virtual_mode implementation
    (git-fixes).

  - efivarfs: fix memory leak in efivarfs_create()
    (git-fixes).

  - efivarfs: revert 'fix memory leak in efivarfs_create()'
    (git-fixes).

  - fuse: fix page dereference after free (bsc#1179213).

  - hv_balloon: disable warning when floor reached
    (git-fixes).

  - i40iw: Fix error handling in i40iw_manage_arp_cache()
    (bsc#1111666)

  - i40iw: Report correct firmware version (bsc#1111666)

  - i40iw: fix NULL pointer dereference on a null wqe
    pointer (bsc#1111666)

  - igc: Fix returning wrong statistics (bsc#1118657).

  - iio: accel: kxcjk1013: Add support for KIOX010A ACPI DSM
    for setting tablet-mode (git-fixes).

  - iio: accel: kxcjk1013: Replace is_smo8500_device with an
    acpi_type enum (git-fixes).

  - iw_cxgb4: fix ECN check on the passive accept
    (bsc#1111666)

  - iw_cxgb4: only reconnect with MPAv1 if the peer aborts
    (bsc#1111666)

  - kABI workaround for usermodehelper changes
    (bsc#1179406).

  - kABI: add back flush_dcache_range (jsc#SLE-16402
    jsc#SLE-16497 bsc#1176109 ltc#187964).

  - libnvdimm/nvdimm/flush: Allow architecture to override
    the flush barrier (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - mac80211: always wind down STA state (git-fixes).

  - mac80211: free sta in sta_info_insert_finish() on errors
    (git-fixes).

  - mlxsw: core: Fix memory leak on module removal
    (bsc#1112374).

  - mm: always have io_remap_pfn_range() set
    pgprot_decrypted() (bsc#1112178).

  - net/tls: Fix kmap usage (bsc#1109837).

  - net/tls: missing received data after fast remote close
    (bsc#1109837).

  - net: DCB: Validate DCB_ATTR_DCB_BUFFER argument
    (bsc#1103990 ).

  - net: ena: fix packet's addresses for rx_offset feature
    (bsc#1174852).

  - net: ena: handle bad request id in ena_netdev
    (git-fixes).

  - net: qed: fix 'maybe uninitialized' warning (bsc#1136460
    jsc#SLE-4691 bsc#1136461 jsc#SLE-4692).

  - net: qed: fix async event callbacks unregistering
    (bsc#1104393 bsc#1104389).

  - net: qede: fix PTP initialization on recovery
    (bsc#1136460 jsc#SLE-4691 bsc#1136461 jsc#SLE-4692).

  - net: qede: fix use-after-free on recovery and AER
    handling (bsc#1136460 jsc#SLE-4691 bsc#1136461
    jsc#SLE-4692).

  - net: thunderx: use spin_lock_bh in
    nicvf_set_rx_mode_task() (bsc#1110096).

  - net_sched: fix a memory leak in atm_tc_init()
    (bsc#1056657 bsc#1056653 bsc#1056787).

  - nfc: s3fwrn5: use signed integer for parsing GPIO
    numbers (git-fixes).

  - nfp: use correct define to return NONE fec
    (bsc#1109837).

  - pinctrl: amd: fix incorrect way to disable debounce
    filter (git-fixes).

  - pinctrl: amd: use higher precision for 512 RtcClk
    (git-fixes).

  - pinctrl: aspeed: Fix GPI only function problem
    (git-fixes).

  - platform/x86: toshiba_acpi: Fix the wrong variable
    assignment (git-fixes).

  - powerpc/32: define helpers to get L1 cache sizes
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/64: flush_inval_dcache_range() becomes
    flush_dcache_range() (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - powerpc/64: reuse PPC32 static inline
    flush_dcache_range() (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - powerpc/mm: Flush cache on memory hot(un)plug
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/pmem: Add flush routines using new pmem store
    and sync instruction (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - powerpc/pmem: Add new instructions for persistent
    storage and sync (jsc#SLE-16402 jsc#SLE-16497
    bsc#1176109 ltc#187964).

  - powerpc/pmem: Avoid the barrier in flush routines
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/pmem: Fix kernel crash due to wrong range value
    usage in flush_dcache_range (jsc#SLE-16497 bsc#1176109
    ltc#187964).

  - powerpc/pmem: Initialize pmem device on newer hardware
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/pmem: Restrict papr_scm to P8 and above
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - powerpc/pmem: Update ppc64 to use the new barrier
    instruction (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109
    ltc#187964).

  - powerpc: Chunk calls to flush_dcache_range in
    arch_*_memory (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109
    ltc#187964 git-fixes).

  - powerpc: define helpers to get L1 icache sizes
    (jsc#SLE-16402 jsc#SLE-16497 bsc#1176109 ltc#187964).

  - qed: fix error return code in qed_iwarp_ll2_start()
    (bsc#1050536 bsc#1050545).

  - qed: suppress 'do not support RoCE & iWARP' flooding on
    HW init (bsc#1050536 bsc#1050545).

  - qed: suppress false-positives interrupt error messages
    on HW init (bsc#1136460 jsc#SLE-4691 bsc#1136461
    jsc#SLE-4692).

  - reboot: fix overflow parsing reboot cpu number
    (bsc#1179421).

  - rxe: correctly calculate iCRC for unaligned payloads
    (bsc#1111666)

  - rxe: fix error completion wr_id and qp_num (bsc#1111666)

  - s390/cio: add cond_resched() in the slow_eval_known_fn()
    loop (bsc#1177805 LTC#188737).

  - s390/cpum_cf,perf: change DFLT_CCERROR counter name
    (bsc#1175916 LTC#187937).

  - s390/dasd: Fix zero write for FBA devices (bsc#1177808
    LTC#188739).

  - s390: kernel/uv: handle length extension properly
    (bsc#1178940 LTC#189323).

  - sched/core: Fix PI boosting between RT and DEADLINE
    tasks (bsc#1112178).

  - sched/x86: SaveFLAGS on context switch (bsc#1112178).

  - scripts/git_sort/git_sort.py: add ceph maintainers git
    tree

  - scsi: RDMA/srpt: Fix a credit leak for aborted commands
    (bsc#1111666)

  - staging: rtl8723bs: Add 024c:0627 to the list of SDIO
    device-ids (git-fixes).

  - svcrdma: Fix page leak in svc_rdma_recv_read_chunk()
    (bsc#1103992).

  - svcrdma: fix bounce buffers for unaligned offsets and
    multiple pages (bsc#1103992).

  - tcp: Set INET_ECN_xmit configuration in
    tcp_reinit_congestion_control (bsc#1109837).

  - tracing: Fix out of bounds write in get_trace_buf
    (bsc#1179403).

  - tty: serial: imx: keep console clocks always on
    (git-fixes).

  - usb: cdc-acm: Add DISABLE_ECHO for Renesas USB Download
    mode (git-fixes).

  - usb: gadget: Fix memleak in gadgetfs_fill_super
    (git-fixes).

  - usb: gadget: f_midi: Fix memleak in f_midi_alloc
    (git-fixes).

  - usb: host: xhci-mtk: avoid runtime suspend when removing
    hcd (git-fixes).

  - usermodehelper: reset umask to default before executing
    user process (bsc#1179406).

  - video: hyperv_fb: Fix the cache type when mapping the
    VRAM (git-fixes).

  - x86/PCI: Avoid AMD FCH XHCI USB PME# from D0 defect
    (git-fixes).

  - x86/PCI: Fix intel_mid_pci.c build error when ACPI is
    not enabled (git-fixes).

  - x86/PCI: Mark Intel C620 MROMs as having non-compliant
    BARs (git-fixes).

  - x86/hyperv: Clarify comment on x2apic mode (git-fixes).

  - x86/hyperv: Make vapic support x2apic mode (git-fixes).

  - x86/microcode/intel: Check patch signature before saving
    microcode for early loading (bsc#1112178).

  - x86/speculation: Allow IBPB to be conditionally enabled
    on CPUs with always-on STIBP (bsc#1112178).

  - x86/sysfb_efi: Add quirks for some devices with swapped
    width and height (git-fixes).

  - xfrm: Fix memleak on xfrm state destroy (bsc#1158775).

  - xfs: revert 'xfs: fix rmap key and record comparison
    functions' (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179429"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27777");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.87.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.87.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.87.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.87.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.87.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.87.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.87.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.87.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
