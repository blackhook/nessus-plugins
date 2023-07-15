#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-618.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123269);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10853", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5391");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-618) (Foreshadow)");
  script_summary(english:"Check for the openSUSE-2019-618 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2018-10853: A flaw was found in KVM in which certain
    instructions such as sgdt/sidt call segmented_write_std
    doesn't propagate access correctly. As such, during
    userspace induced exception, the guest can incorrectly
    assume that the exception happened in the kernel and
    panic (bnc#1097104).

  - CVE-2018-10876: A flaw was found in the ext4 filesystem
    code. A use-after-free is possible in
    ext4_ext_remove_space() function when mounting and
    operating a crafted ext4 image. (bnc#1099811)

  - CVE-2018-10877: Linux kernel ext4 filesystem is
    vulnerable to an out-of-bound access in the
    ext4_ext_drop_refs() function when operating on a
    crafted ext4 filesystem image. (bnc#1099846)

  - CVE-2018-10878: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bounds write and a
    denial of service or unspecified other impact is
    possible by mounting and operating a crafted ext4
    filesystem image. (bnc#1099813)

  - CVE-2018-10879: A flaw was found in the ext4 filesystem.
    A local user can cause a use-after-free in
    ext4_xattr_set_entry function and a denial of service or
    unspecified other impact may occur by renaming a file in
    a crafted ext4 filesystem image. (bnc#1099844)

  - CVE-2018-10880: Linux kernel is vulnerable to a
    stack-out-of-bounds write in the ext4 filesystem code
    when mounting and writing to a crafted ext4 image in
    ext4_update_inline_data(). An attacker could use this to
    cause a system crash and a denial of service.
    (bnc#1099845)

  - CVE-2018-10881: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bound access in
    ext4_get_group_info function, a denial of service, and a
    system crash by mounting and operating on a crafted ext4
    filesystem image. (bnc#1099864)

  - CVE-2018-10882: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bound write in in
    fs/jbd2/transaction.c code, a denial of service, and a
    system crash by unmounting a crafted ext4 filesystem
    image. (bnc#1099849)

  - CVE-2018-10883: A flaw was found in the ext4 filesystem.
    A local user can cause an out-of-bounds write in
    jbd2_journal_dirty_metadata(), a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image. (bnc#1099863)

  - CVE-2018-3620: Systems with microprocessors utilizing
    speculative execution and address translations may allow
    unauthorized disclosure of information residing in the
    L1 data cache to an attacker with local user access via
    a terminal page fault and a side-channel analysis
    (bnc#1087081).

  - CVE-2018-3646: Systems with microprocessors utilizing
    speculative execution and address translations may allow
    unauthorized disclosure of information residing in the
    L1 data cache to an attacker with local user access with
    guest OS privilege via a terminal page fault and a
    side-channel analysis (bnc#1089343 bnc#1104365).

  - CVE-2018-5391 aka 'FragmentSmack': A flaw in the IP
    packet reassembly could be used by remote attackers to
    consume lots of CPU time (bnc#1103097).

The following non-security bugs were fixed :

  - afs: Fix directory permissions check (bsc#1101828).

  - bdi: Move cgroup bdi_writeback to a dedicated low
    concurrency workqueue (bsc#1101867).

  - be2net: gather debug info and reset adapter (only for
    Lancer) on a tx-timeout (bsc#1086288).

  - be2net: Update the driver version to 12.0.0.0
    (bsc#1086288 ).

  - befs_lookup(): use d_splice_alias() (bsc#1101844).

  - block: Fix transfer when chunk sectors exceeds max
    (bsc#1101874).

  - bpf, ppc64: fix unexpected r0=0 exit path inside
    bpf_xadd (bsc#1083647).

  - branch-check: fix long->int truncation when profiling
    branches (bsc#1101116,).

  - cdrom: do not call check_disk_change() inside
    cdrom_open() (bsc#1101872).

  - compiler.h: enable builtin overflow checkers and add
    fallback code (bsc#1101116,).

  - cpu/hotplug: Make bringup/teardown of smp threads
    symmetric (bsc#1089343).

  - cpu/hotplug: Provide knobs to control SMT (bsc#1089343).

  - cpu/hotplug: Split do_cpu_down() (bsc#1089343).

  - delayacct: fix crash in delayacct_blkio_end() after
    delayacct init failure (bsc#1104066).

  - dm: add writecache target (bsc#1101116,).

  - dm writecache: support optional offset for start of
    device (bsc#1101116,).

  - dm writecache: use 2-factor allocator arguments
    (bsc#1101116,).

  - EDAC: Add missing MEM_LRDDR4 entry in edac_mem_types[]
    (bsc#1103886).

  - EDAC: Drop duplicated array of strings for memory type
    names (bsc#1103886).

  - ext2: fix a block leak (bsc#1101875).

  - ext4: add more mount time checks of the superblock
    (bsc#1101900).

  - ext4: bubble errors from ext4_find_inline_data_nolock()
    up to ext4_iget() (bsc#1101896).

  - ext4: check for allocation block validity with block
    group locked (bsc#1104495).

  - ext4: check superblock mapped prior to committing
    (bsc#1101902).

  - ext4: do not update s_last_mounted of a frozen fs
    (bsc#1101841).

  - ext4: factor out helper ext4_sample_last_mounted()
    (bsc#1101841).

  - ext4: fix check to prevent initializing reserved inodes
    (bsc#1104319).

  - ext4: fix false negatives *and* false positives in
    ext4_check_descriptors() (bsc#1103445).

  - ext4: fix fencepost error in check for inode count
    overflow during resize (bsc#1101853).

  - ext4: fix inline data updates with checksums enabled
    (bsc#1104494).

  - ext4: include the illegal physical block in the bad map
    ext4_error msg (bsc#1101903).

  - ext4: report delalloc reserve as non-free in statfs for
    project quota (bsc#1101843).

  - ext4: update mtime in ext4_punch_hole even if no blocks
    are released (bsc#1101895).

  - f2fs: call unlock_new_inode() before d_instantiate()
    (bsc#1101837).

  - fix io_destroy()/aio_complete() race (bsc#1101852).

  - Force log to disk before reading the AGF during a fstrim
    (bsc#1101893).

  - fscache: Fix hanging wait on page discarded by writeback
    (bsc#1101885).

  - fs: clear writeback errors in inode_init_always
    (bsc#1101882).

  - fs: do not scan the inode cache before SB_BORN is set
    (bsc#1101883).

  - hns3: fix unused function warning (bsc#1104353).

  - hns3pf: do not check handle during mqprio offload
    (bsc#1104353 ).

  - hns3pf: fix hns3_del_tunnel_port() (bsc#1104353).

  - hns3pf: Fix some harmless copy and paste bugs
    (bsc#1104353 ).

  - hv_netvsc: Fix napi reschedule while receive completion
    is busy ().

  - hv/netvsc: Fix NULL dereference at single queue mode
    fallback (bsc#1104708).

  - hwmon: (asus_atk0110) Replace deprecated device register
    call (bsc#1103363).

  - IB/hns: Annotate iomem pointers correctly (bsc#1104427
    ).

  - IB/hns: Avoid compile test under non 64bit environments
    (bsc#1104427).

  - IB/hns: Declare local functions 'static' (bsc#1104427 ).

  - IB/hns: fix boolreturn.cocci warnings (bsc#1104427).

  - IB/hns: Fix for checkpatch.pl comment style warnings
    (bsc#1104427).

  - IB/hns: fix memory leak on ah on error return path
    (bsc#1104427 ).

  - IB/hns: fix returnvar.cocci warnings (bsc#1104427).

  - IB/hns: fix semicolon.cocci warnings (bsc#1104427).

  - IB/hns: Fix the bug of polling cq failed for loopback
    Qps (bsc#1104427). Refresh
    patches.suse/0001-IB-hns-checking-for-IS_ERR-instead-of-
    NULL.patch.

  - IB/hns: Fix the bug with modifying the MAC address
    without removing the driver (bsc#1104427).

  - IB/hns: Fix the bug with rdma operation (bsc#1104427 ).

  - IB/hns: Fix the bug with wild pointer when destroy rc qp
    (bsc#1104427).

  - IB/hns: include linux/interrupt.h (bsc#1104427).

  - IB/hns: Support compile test for hns RoCE driver
    (bsc#1104427 ).

  - IB/hns: Use zeroing memory allocator instead of
    allocator/memset (bsc#1104427).

  - isofs: fix potential memory leak in mount option parsing
    (bsc#1101887).

  - jump_label: Fix concurrent static_key_enable/disable()
    (bsc#1089343).

  - jump_label: Provide hotplug context variants
    (bsc#1089343).

  - jump_label: Reorder hotplug lock and jump_label_lock
    (bsc#1089343).

  - kabi/severities: Allow kABI changes for kvm/x86 (except
    for kvm_x86_ops)

  - kabi/severities: ignore qla2xxx as all symbols are
    internal

  - kabi/severities: ignore x86_kvm_ops; lttng-modules would
    have to be adjusted in case they depend on this
    particular change

  - kabi/severities: Relax kvm_vcpu_* kABI breakage

  - media: rc: oops in ir_timer_keyup after device unplug
    (bsc#1090888).

  - mm: fix __gup_device_huge vs unmap (bsc#1101839).

  - net: hns3: Add a check for client instance init state
    (bsc#1104353).

  - net: hns3: add a mask initialization for mac_vlan table
    (bsc#1104353).

  - net: hns3: Add *Asserting Reset* mailbox message &
    handling in VF (bsc#1104353).

  - net: hns3: add Asym Pause support to phy default
    features (bsc#1104353).

  - net: hns3: Add dcb netlink interface for the support of
    DCB feature (bsc#1104353).

  - net: hns3: Add DCB support when interacting with network
    stack (bsc#1104353).

  - net: hns3: Add ethtool interface for vlan filter
    (bsc#1104353 ).

  - net: hns3: add ethtool_ops.get_channels support for VF
    (bsc#1104353).

  - net: hns3: add ethtool_ops.get_coalesce support to PF
    (bsc#1104353).

  - net: hns3: add ethtool_ops.set_coalesce support to PF
    (bsc#1104353).

  - net: hns3: add ethtool -p support for fiber port
    (bsc#1104353 ).

  - net: hns3: add ethtool related offload command
    (bsc#1104353 ).

  - net: hns3: Add Ethtool support to HNS3 driver
    (bsc#1104353 ).

  - net: hns3: add existence checking before adding unicast
    mac address (bsc#1104353).

  - net: hns3: add existence check when remove old uc mac
    address (bsc#1104353).

  - net: hns3: add feature check when feature changed
    (bsc#1104353 ).

  - net: hns3: add get_link support to VF (bsc#1104353).

  - net: hns3: add get/set_coalesce support to VF
    (bsc#1104353 ).

  - net: hns3: add handling vlan tag offload in bd
    (bsc#1104353 ).

  - net: hns3: Add hclge_dcb module for the support of DCB
    feature (bsc#1104353).

  - net: hns3: Add HNS3 Acceleration Engine & Compatibility
    Layer Support (bsc#1104353).

  - net: hns3: Add HNS3 driver to kernel build framework &
    MAINTAINERS (bsc#1104353).

  - net: hns3: Add hns3_get_handle macro in hns3 driver
    (bsc#1104353 ).

  - net: hns3: Add HNS3 IMP(Integrated Mgmt Proc) Cmd
    Interface Support (bsc#1104353).

  - net: hns3: Add HNS3 VF driver to kernel build framework
    (bsc#1104353).

  - net: hns3: Add HNS3 VF HCL(Hardware Compatibility Layer)
    Support (bsc#1104353).

  - net: hns3: Add HNS3 VF IMP(Integrated Management Proc)
    cmd interface (bsc#1104353).

  - net: hns3: add int_gl_idx setup for TX and RX queues
    (bsc#1104353).

  - net: hns3: add int_gl_idx setup for VF (bsc#1104353 ).

  - net: hns3: Add mac loopback selftest support in hns3
    driver (bsc#1104353).

  - net: hns3: Add mailbox interrupt handling to PF driver
    (bsc#1104353).

  - net: hns3: Add mailbox support to PF driver (bsc#1104353
    ).

  - net: hns3: Add mailbox support to VF driver (bsc#1104353
    ).

  - net: hns3: add manager table initialization for hardware
    (bsc#1104353).

  - net: hns3: Add MDIO support to HNS3 Ethernet driver for
    hip08 SoC (bsc#1104353).

  - net: hns3: Add missing break in misc_irq_handle
    (bsc#1104353 ).

  - net: hns3: Add more packet size statisctics (bsc#1104353
    ).

  - net: hns3: add MTU initialization for hardware
    (bsc#1104353 ).

  - net: hns3: add net status led support for fiber port
    (bsc#1104353).

  - net: hns3: add nic_client check when initialize roce
    base information (bsc#1104353).

  - net: hns3: add querying speed and duplex support to VF
    (bsc#1104353).

  - net: hns3: Add repeat address checking for setting mac
    address (bsc#1104353).

  - net: hns3: Add reset interface implementation in client
    (bsc#1104353).

  - net: hns3: Add reset process in hclge_main (bsc#1104353
    ).

  - net: hns3: Add reset service task for handling reset
    requests (bsc#1104353).

  - net: hns3: add result checking for VF when modify
    unicast mac address (bsc#1104353).

  - net: hns3: Add some interface for the support of DCB
    feature (bsc#1104353).

  - net: hns3: Adds support for led locate command for
    copper port (bsc#1104353).

  - net: hns3: Add STRP_TAGP field support for hardware
    revision 0x21 (bsc#1104353).

  - net: hns3: Add support for dynamically buffer
    reallocation (bsc#1104353).

  - net: hns3: add support for ETHTOOL_GRXFH (bsc#1104353 ).

  - net: hns3: add support for get_regs (bsc#1104353).

  - net: hns3: Add support for IFF_ALLMULTI flag
    (bsc#1104353 ).

  - net: hns3: Add support for misc interrupt (bsc#1104353
    ).

  - net: hns3: add support for nway_reset (bsc#1104353).

  - net: hns3: Add support for PFC setting in TM module
    (bsc#1104353 ).

  - net: hns3: Add support for port shaper setting in TM
    module (bsc#1104353).

  - net: hns3: add support for querying advertised pause
    frame by ethtool ethx (bsc#1104353).

  - net: hns3: add support for querying pfc puase packets
    statistic (bsc#1104353).

  - net: hns3: add support for set_link_ksettings
    (bsc#1104353 ).

  - net: hns3: add support for set_pauseparam (bsc#1104353
    ).

  - net: hns3: add support for set_ringparam (bsc#1104353 ).

  - net: hns3: add support for set_rxnfc (bsc#1104353).

  - net: hns3: Add support for tx_accept_tag2 and
    tx_accept_untag2 config (bsc#1104353).

  - net: hns3: add support for VF driver inner interface
    hclgevf_ops.get_tqps_and_rss_info (bsc#1104353).

  - net: hns3: Add support of hardware rx-vlan-offload to
    HNS3 VF driver (bsc#1104353).

  - net: hns3: Add support of HNS3 Ethernet Driver for hip08
    SoC (bsc#1104353).

  - net: hns3: Add support of .sriov_configure in HNS3
    driver (bsc#1104353).

  - net: hns3: Add support of the HNAE3 framework
    (bsc#1104353 ).

  - net: hns3: Add support of TX Scheduler & Shaper to HNS3
    driver (bsc#1104353).

  - net: hns3: Add support to change MTU in HNS3 hardware
    (bsc#1104353).

  - net: hns3: Add support to enable TX/RX promisc mode for
    H/W rev(0x21) (bsc#1104353).

  - net: hns3: add support to modify tqps number
    (bsc#1104353 ).

  - net: hns3: add support to query tqps number (bsc#1104353
    ).

  - net: hns3: Add support to re-initialize the hclge device
    (bsc#1104353).

  - net: hns3: Add support to request VF Reset to PF
    (bsc#1104353 ).

  - net: hns3: Add support to reset the enet/ring mgmt layer
    (bsc#1104353).

  - net: hns3: add support to update flow control settings
    after autoneg (bsc#1104353).

  - net: hns3: Add tc-based TM support for sriov enabled
    port (bsc#1104353).

  - net: hns3: Add timeout process in hns3_enet (bsc#1104353
    ).

  - net: hns3: Add VF Reset device state and its handling
    (bsc#1104353).

  - net: hns3: Add VF Reset Service Task to support event
    handling (bsc#1104353).

  - net: hns3: add vlan offload config command (bsc#1104353
    ).

  - net: hns3: change GL update rate (bsc#1104353).

  - net: hns3: Change PF to add ring-vect binding & resetQ
    to mailbox (bsc#1104353).

  - net: hns3: Change return type of hnae3_register_ae_algo
    (bsc#1104353).

  - net: hns3: Change return type of hnae3_register_ae_dev
    (bsc#1104353).

  - net: hns3: Change return value in hnae3_register_client
    (bsc#1104353).

  - net: hns3: Changes required in PF mailbox to support VF
    reset (bsc#1104353).

  - net: hns3: Changes to make enet watchdog timeout func
    common for PF/VF (bsc#1104353).

  - net: hns3: Changes to support ARQ(Asynchronous Receive
    Queue) (bsc#1104353).

  - net: hns3: change the returned tqp number by ethtool -x
    (bsc#1104353).

  - net: hns3: change the time interval of int_gl
    calculating (bsc#1104353).

  - net: hns3: change the unit of GL value macro
    (bsc#1104353 ).

  - net: hns3: change TM sched mode to TC-based mode when
    SRIOV enabled (bsc#1104353).

  - net: hns3: check for NULL function pointer in
    hns3_nic_set_features (bsc#1104353).

  - net: hns3: Cleanup for endian issue in hns3 driver
    (bsc#1104353 ).

  - net: hns3: Cleanup for non-static function in hns3
    driver (bsc#1104353).

  - net: hns3: Cleanup for ROCE capability flag in ae_dev
    (bsc#1104353).

  - net: hns3: Cleanup for shifting true in hns3 driver
    (bsc#1104353 ).

  - net: hns3: Cleanup for struct that used to send cmd to
    firmware (bsc#1104353).

  - net: hns3: Cleanup indentation for Kconfig in the the
    hisilicon folder (bsc#1104353).

  - net: hns3: cleanup mac auto-negotiation state query
    (bsc#1104353 ).

  - net: hns3: cleanup mac auto-negotiation state query in
    hclge_update_speed_duplex (bsc#1104353).

  - net: hns3: cleanup of return values in
    hclge_init_client_instance() (bsc#1104353).

  - net: hns3: Clear TX/RX rings when stopping port &
    un-initializing client (bsc#1104353).

  - net: hns3: Consistently using GENMASK in hns3 driver
    (bsc#1104353).

  - net: hns3: converting spaces into tabs to avoid
    checkpatch.pl warning (bsc#1104353).

  - net: hns3: Disable VFs change rxvlan offload status
    (bsc#1104353 ).

  - net: hns3: Disable vf vlan filter when vf vlan table is
    full (bsc#1104353).

  - net: hns3: ensure media_type is uninitialized
    (bsc#1104353 ).

  - net: hns3: export pci table of hclge and hclgevf to
    userspace (bsc#1104353).

  - net: hns3: fix a bug about hns3_clean_tx_ring
    (bsc#1104353 ).

  - net: hns3: fix a bug for phy supported feature
    initialization (bsc#1104353).

  - net: hns3: fix a bug in hclge_uninit_client_instance
    (bsc#1104353).

  - net: hns3: fix a bug in hns3_driv_to_eth_caps
    (bsc#1104353 ).

  - net: hns3: fix a bug when alloc new buffer (bsc#1104353
    ).

  - net: hns3: fix a bug when getting phy address from
    NCL_config file (bsc#1104353).

  - net: hns3: fix a dead loop in hclge_cmd_csq_clean
    (bsc#1104353 ).

  - net: hns3: fix a handful of spelling mistakes
    (bsc#1104353 ).

  - net: hns3: Fix a loop index error of tqp statistics
    query (bsc#1104353).

  - net: hns3: Fix a misuse to devm_free_irq (bsc#1104353 ).

  - net: hns3: Fix an error handling path in
    'hclge_rss_init_hw()' (bsc#1104353).

  - net: hns3: Fix an error macro definition of
    HNS3_TQP_STAT (bsc#1104353).

  - net: hns3: Fix an error of total drop packet statistics
    (bsc#1104353).

  - net: hns3: Fix a response data read error of tqp
    statistics query (bsc#1104353).

  - net: hns3: fix endian issue when PF get mbx message flag
    (bsc#1104353).

  - net: hns3: fix error type definition of return value
    (bsc#1104353).

  - net: hns3: Fixes API to fetch ethernet header length
    with kernel default (bsc#1104353).

  - net: hns3: Fixes error reported by Kbuild and internal
    review (bsc#1104353).

  - net: hns3: Fixes initalization of RoCE handle and makes
    it conditional (bsc#1104353).

  - net: hns3: Fixes initialization of phy address from
    firmware (bsc#1104353).

  - net: hns3: Fixes kernel panic issue during rmmod hns3
    driver (bsc#1104353).

  - net: hns3: Fixes ring-to-vector map-and-unmap command
    (bsc#1104353).

  - net: hns3: Fixes the back pressure setting when sriov is
    enabled (bsc#1104353).

  - net: hns3: Fixes the command used to unmap ring from
    vector (bsc#1104353).

  - net: hns3: Fixes the default VLAN-id of PF (bsc#1104353
    ).

  - net: hns3: Fixes the error legs in hclge_init_ae_dev
    function (bsc#1104353).

  - net: hns3: Fixes the ether address copy with appropriate
    API (bsc#1104353).

  - net: hns3: Fixes the initialization of MAC address in
    hardware (bsc#1104353).

  - net: hns3: Fixes the init of the VALID BD info in the
    descriptor (bsc#1104353).

  - net: hns3: Fixes the missing PCI iounmap for various
    legs (bsc#1104353).

  - net: hns3: Fixes the missing u64_stats_fetch_begin_irq
    in 64-bit stats fetch (bsc#1104353).

  - net: hns3: Fixes the out of bounds access in
    hclge_map_tqp (bsc#1104353).

  - net: hns3: Fixes the premature exit of loop when
    matching clients (bsc#1104353).

  - net: hns3: fixes the ring index in hns3_fini_ring
    (bsc#1104353 ).

  - net: hns3: Fixes the state to indicate client-type
    initialization (bsc#1104353).

  - net: hns3: Fixes the static checker error warning in
    hns3_get_link_ksettings() (bsc#1104353).

  - net: hns3: Fixes the static check warning due to missing
    unsupp L3 proto check (bsc#1104353).

  - net: hns3: Fixes the wrong IS_ERR check on the returned
    phydev value (bsc#1104353).

  - net: hns3: fix for buffer overflow smatch warning
    (bsc#1104353 ).

  - net: hns3: fix for changing MTU (bsc#1104353).

  - net: hns3: fix for cleaning ring problem (bsc#1104353 ).

  - net: hns3: Fix for CMDQ and Misc. interrupt init order
    problem (bsc#1104353).

  - net: hns3: fix for coal configuation lost when setting
    the channel (bsc#1104353).

  - net: hns3: fix for coalesce configuration lost during
    reset (bsc#1104353).

  - net: hns3: Fix for deadlock problem occurring when
    unregistering ae_algo (bsc#1104353).

  - net: hns3: Fix for DEFAULT_DV when dev does not support
    DCB (bsc#1104353).

  - net: hns3: Fix for fiber link up problem (bsc#1104353 ).

  - net: hns3: fix for getting advertised_caps in
    hns3_get_link_ksettings (bsc#1104353).

  - net: hns3: fix for getting autoneg in
    hns3_get_link_ksettings (bsc#1104353).

  - net: hns3: fix for getting auto-negotiation state in
    hclge_get_autoneg (bsc#1104353).

  - net: hns3: fix for getting wrong link mode problem
    (bsc#1104353 ).

  - net: hns3: Fix for hclge_reset running repeatly problem
    (bsc#1104353).

  - net: hns3: Fix for hns3 module is loaded multiple times
    problem (bsc#1104353).

  - net: hns3: fix for ipv6 address loss problem after
    setting channels (bsc#1104353).

  - net: hns3: fix for loopback failure when vlan filter is
    enable (bsc#1104353).

  - net: hns3: fix for netdev not running problem after
    calling net_stop and net_open (bsc#1104353).

  - net: hns3: Fix for netdev not running problem after
    calling net_stop and net_open (bsc#1104353).

  - net: hns3: fix for not initializing VF rss_hash_key
    problem (bsc#1104353).

  - net: hns3: fix for not returning problem in
    get_link_ksettings when phy exists (bsc#1104353).

  - net: hns3: fix for not setting pause parameters
    (bsc#1104353 ).

  - net: hns3: Fix for not setting rx private buffer size to
    zero (bsc#1104353).

  - net: hns3: Fix for packet loss due wrong filter config
    in VLAN tbls (bsc#1104353).

  - net: hns3: fix for pause configuration lost during reset
    (bsc#1104353).

  - net: hns3: Fix for PF mailbox receving unknown message
    (bsc#1104353).

  - net: hns3: fix for phy_addr error in
    hclge_mac_mdio_config (bsc#1104353).

  - net: hns3: Fix for phy not link up problem after
    resetting (bsc#1104353).

  - net: hns3: Fix for pri to tc mapping in TM (bsc#1104353
    ).

  - net: hns3: fix for returning wrong value problem in
    hns3_get_rss_indir_size (bsc#1104353).

  - net: hns3: fix for returning wrong value problem in
    hns3_get_rss_key_size (bsc#1104353).

  - net: hns3: fix for RSS configuration loss problem during
    reset (bsc#1104353).

  - net: hns3: Fix for rx priv buf allocation when DCB is
    not supported (bsc#1104353).

  - net: hns3: Fix for rx_priv_buf_alloc not setting rx
    shared buffer (bsc#1104353).

  - net: hns3: Fix for service_task not running problem
    after resetting (bsc#1104353).

  - net: hns3: Fix for setting mac address when resetting
    (bsc#1104353).

  - net: hns3: fix for setting MTU (bsc#1104353).

  - net: hns3: Fix for setting rss_size incorrectly
    (bsc#1104353 ).

  - net: hns3: Fix for the NULL pointer problem occurring
    when initializing ae_dev failed (bsc#1104353).

  - net: hns3: fix for the wrong shift problem in
    hns3_set_txbd_baseinfo (bsc#1104353).

  - net: hns3: fix for updating fc_mode_last_time
    (bsc#1104353 ).

  - net: hns3: fix for use-after-free when setting ring
    parameter (bsc#1104353).

  - net: hns3: Fix for VF mailbox cannot receiving PF
    response (bsc#1104353).

  - net: hns3: Fix for VF mailbox receiving unknown message
    (bsc#1104353).

  - net: hns3: fix for vlan table lost problem when
    resetting (bsc#1104353).

  - net: hns3: Fix for vxlan tx checksum bug (bsc#1104353 ).

  - net: hns3: Fix initialization when cmd is not supported
    (bsc#1104353).

  - net: hns3: fix length overflow when
    CONFIG_ARM64_64K_PAGES (bsc#1104353).

  - net: hns3: fix NULL pointer dereference before null
    check (bsc#1104353).

  - net: hns3: fix return value error of
    hclge_get_mac_vlan_cmd_status() (bsc#1104353).

  - net: hns3: fix rx path skb->truesize reporting bug
    (bsc#1104353 ).

  - net: hns3: Fix setting mac address error (bsc#1104353 ).

  - net: hns3: Fix spelling errors (bsc#1104353).

  - net: hns3: fix spelling mistake: 'capabilty' ->
    'capability' (bsc#1104353).

  - net: hns3: fix the bug of hns3_set_txbd_baseinfo
    (bsc#1104353 ).

  - net: hns3: fix the bug when map buffer fail (bsc#1104353
    ).

  - net: hns3: fix the bug when reuse command description in
    hclge_add_mac_vlan_tbl (bsc#1104353).

  - net: hns3: Fix the missing client list node
    initialization (bsc#1104353).

  - net: hns3: fix the ops check in hns3_get_rxnfc
    (bsc#1104353 ).

  - net: hns3: fix the queue id for tqp enable&&reset
    (bsc#1104353 ).

  - net: hns3: fix the ring count for ETHTOOL_GRXRINGS
    (bsc#1104353 ).

  - net: hns3: fix the TX/RX ring.queue_index in
    hns3_ring_get_cfg (bsc#1104353).

  - net: hns3: fix the VF queue reset flow error
    (bsc#1104353 ).

  - net: hns3: fix to correctly fetch l4 protocol outer
    header (bsc#1104353).

  - net: hns3: Fix to support autoneg only for port attached
    with phy (bsc#1104353).

  - net: hns3: Fix typo error for feild in hclge_tm
    (bsc#1104353 ).

  - net: hns3: free the ring_data structrue when change tqps
    (bsc#1104353).

  - net: hns3: get rss_size_max from configuration but not
    hardcode (bsc#1104353).

  - net: hns3: get vf count by pci_sriov_get_totalvfs
    (bsc#1104353 ).

  - net: hns3: hclge_inform_reset_assert_to_vf() can be
    static (bsc#1104353).

  - net: hns3: hns3:fix a bug about statistic counter in
    reset process (bsc#1104353).

  - net: hns3: hns3_get_channels() can be static
    (bsc#1104353 ).

  - net: hns3: Increase the default depth of bucket for TM
    shaper (bsc#1104353).

  - net: hns3: increase the max time for IMP handle command
    (bsc#1104353).

  - net: hns3: make local functions static (bsc#1104353 ).

  - net: hns3: Mask the packet statistics query when NIC is
    down (bsc#1104353).

  - net: hns3: Modify the update period of packet statistics
    (bsc#1104353).

  - net: hns3: never send command queue message to IMP when
    reset (bsc#1104353).

  - net: hns3: Optimize PF CMDQ interrupt switching process
    (bsc#1104353).

  - net: hns3: Optimize the PF's process of updating
    multicast MAC (bsc#1104353).

  - net: hns3: Optimize the VF's process of updating
    multicast MAC (bsc#1104353).

  - net: hns3: reallocate tx/rx buffer after changing mtu
    (bsc#1104353).

  - net: hns3: refactor GL update function (bsc#1104353 ).

  - net: hns3: refactor interrupt coalescing init function
    (bsc#1104353).

  - net: hns3: Refactor mac_init function (bsc#1104353).

  - net: hns3: Refactor of the reset interrupt handling
    logic (bsc#1104353).

  - net: hns3: Refactors the requested reset & pending reset
    handling code (bsc#1104353).

  - net: hns3: refactor the coalesce related struct
    (bsc#1104353 ).

  - net: hns3: refactor the get/put_vector function
    (bsc#1104353 ).

  - net: hns3: refactor the hclge_get/set_rss function
    (bsc#1104353 ).

  - net: hns3: refactor the hclge_get/set_rss_tuple function
    (bsc#1104353).

  - net: hns3: Refactor the initialization of command queue
    (bsc#1104353).

  - net: hns3: refactor the loopback related function
    (bsc#1104353 ).

  - net: hns3: Refactor the mapping of tqp to vport
    (bsc#1104353 ).

  - net: hns3: Refactor the skb receiving and transmitting
    function (bsc#1104353).

  - net: hns3: remove a couple of redundant assignments
    (bsc#1104353 ).

  - net: hns3: remove add/del_tunnel_udp in hns3_enet module
    (bsc#1104353).

  - net: hns3: Remove a useless member of struct hns3_stats
    (bsc#1104353).

  - net: hns3: Remove error log when getting pfc stats fails
    (bsc#1104353).

  - net: hns3: Remove packet statistics in the range of
    8192~12287 (bsc#1104353).

  - net: hns3: remove redundant memset when alloc buffer
    (bsc#1104353).

  - net: hns3: remove redundant semicolon (bsc#1104353).

  - net: hns3: Remove repeat statistic of rx_errors
    (bsc#1104353 ).

  - net: hns3: Removes unnecessary check when clearing TX/RX
    rings (bsc#1104353).

  - net: hns3: remove TSO config command from VF driver
    (bsc#1104353 ).

  - net: hns3: remove unnecessary pci_set_drvdata() and
    devm_kfree() (bsc#1104353).

  - net: hns3: remove unused GL setup function (bsc#1104353
    ).

  - net: hns3: remove unused hclgevf_cfg_func_mta_filter
    (bsc#1104353).

  - net: hns3: Remove unused led control code (bsc#1104353
    ).

  - net: hns3: report the function type the same line with
    hns3_nic_get_stats64 (bsc#1104353).

  - net: hns3: set the cmdq out_vld bit to 0 after used
    (bsc#1104353 ).

  - net: hns3: set the max ring num when alloc netdev
    (bsc#1104353 ).

  - net: hns3: Setting for fc_mode and dcb enable flag in TM
    module (bsc#1104353).

  - net: hns3: Support for dynamically assigning tx buffer
    to TC (bsc#1104353).

  - net: hns3: Unified HNS3 (VF|PF) Ethernet Driver for
    hip08 SoC (bsc#1104353).

  - net: hns3: unify the pause params setup function
    (bsc#1104353 ).

  - net: hns3: Unify the strings display of packet
    statistics (bsc#1104353).

  - net: hns3: Updates MSI/MSI-X alloc/free APIs(depricated)
    to new APIs (bsc#1104353).

  - net: hns3: Updates RX packet info fetch in case of multi
    BD (bsc#1104353).

  - net: hns3: Use enums instead of magic number in
    hclge_is_special_opcode (bsc#1104353).

  - net: hns3: VF should get the real rss_size instead of
    rss_size_max (bsc#1104353).

  - net: lan78xx: Fix race in tx pending skb size
    calculation (bsc#1100132).

  - net: lan78xx: fix rx handling before first packet is
    send (bsc#1100132).

  - net: qmi_wwan: add BroadMobi BM806U 2020:2033
    (bsc#1087092).

  - net: qmi_wwan: Add Netgear Aircard 779S (bsc#1090888).

  - net-usb: add qmi_wwan if on lte modem wistron neweb
    d18q1 (bsc#1087092).

  - net: usb: asix: replace mii_nway_restart in resume path
    (bsc#1100132).

  - orangefs: report attributes_mask and attributes for
    statx (bsc#1101832).

  - orangefs: set i_size on new symlink (bsc#1101845).

  - overflow.h: Add allocation size calculation helpers
    (bsc#1101116,).

  - powerpc/64: Add GENERIC_CPU support for little endian
    ().

  - powerpc/fadump: handle crash memory ranges array index
    overflow (bsc#1103269).

  - powerpc/fadump: merge adjacent memory ranges to reduce
    PT_LOAD segements (bsc#1103269).

  - powerpc/pkeys: Deny read/write/execute by default
    (bsc#1097577).

  - powerpc/pkeys: Fix calculation of total pkeys
    (bsc#1097577).

  - powerpc/pkeys: Give all threads control of their key
    permissions (bsc#1097577).

  - powerpc/pkeys: key allocation/deallocation must not
    change pkey registers (bsc#1097577).

  - powerpc/pkeys: make protection key 0 less special
    (bsc#1097577).

  - powerpc/pkeys: Preallocate execute-only key
    (bsc#1097577).

  - powerpc/pkeys: Save the pkey registers before fork
    (bsc#1097577).

  - qed*: Add link change count value to ethtool statistics
    display (bsc#1086314).

  - qed: Add qed APIs for PHY module query (bsc#1086314 ).

  - qed: Add srq core support for RoCE and iWARP
    (bsc#1086314 ).

  - qede: Add driver callbacks for eeprom module query
    (bsc#1086314 ).

  - qedf: Add get_generic_tlv_data handler (bsc#1086317).

  - qedf: Add support for populating ethernet TLVs
    (bsc#1086317).

  - qed: fix spelling mistake 'successffuly' ->
    'successfully' (bsc#1086314).

  - qedi: Add get_generic_tlv_data handler (bsc#1086315).

  - qedi: Add support for populating ethernet TLVs
    (bsc#1086315).

  - qed: Make some functions static (bsc#1086314).

  - qed: remove redundant functions qed_get_cm_pq_idx_rl
    (bsc#1086314).

  - qed: remove redundant functions
    qed_set_gft_event_id_cm_hdr (bsc#1086314).

  - qed: remove redundant pointer 'name' (bsc#1086314).

  - qed: use dma_zalloc_coherent instead of allocator/memset
    (bsc#1086314).

  - qed*: Utilize FW 8.37.2.0 (bsc#1086314).

  - rdma/hns: Add 64KB page size support for hip08
    (bsc#1104427 ).

  - rdma/hns: Add command queue support for hip08 RoCE
    driver (bsc#1104427).

  - rdma/hns: Add CQ operations support for hip08 RoCE
    driver (bsc#1104427).

  - rdma/hns: Add detailed comments for mb() call
    (bsc#1104427 ).

  - rdma/hns: Add eq support of hip08 (bsc#1104427).

  - rdma/hns: Add gsi qp support for modifying qp in hip08
    (bsc#1104427).

  - rdma/hns: Add mailbox's implementation for hip08 RoCE
    driver (bsc#1104427).

  - rdma/hns: Add modify CQ support for hip08 (bsc#1104427
    ).

  - rdma/hns: Add names to function arguments in function
    pointers (bsc#1104427).

  - rdma/hns: Add profile support for hip08 driver
    (bsc#1104427 ).

  - rdma/hns: Add QP operations support for hip08 SoC
    (bsc#1104427 ).

  - rdma/hns: Add releasing resource operation in error
    branch (bsc#1104427).

  - rdma/hns: Add rereg mr support for hip08 (bsc#1104427 ).

  - rdma/hns: Add reset process for RoCE in hip08
    (bsc#1104427 ).

  - rdma/hns: Add return operation when configured global
    param fail (bsc#1104427).

  - rdma/hns: Add rq inline data support for hip08 RoCE
    (bsc#1104427 ).

  - rdma/hns: Add rq inline flags judgement (bsc#1104427 ).

  - rdma/hns: Add sq_invld_flg field in QP context
    (bsc#1104427 ).

  - rdma/hns: Add support for processing send wr and receive
    wr (bsc#1104427).

  - rdma/hns: Add the interfaces to support multi hop
    addressing for the contexts in hip08 (bsc#1104427).

  - rdma/hns: Adjust the order of cleanup hem table
    (bsc#1104427 ).

  - rdma/hns: Assign dest_qp when deregistering mr
    (bsc#1104427 ).

  - rdma/hns: Assign the correct value for tx_cqn
    (bsc#1104427 ).

  - rdma/hns: Assign zero for pkey_index of wc in hip08
    (bsc#1104427 ).

  - rdma/hns: Avoid NULL pointer exception (bsc#1104427 ).

  - rdma/hns: Bugfix for cq record db for kernel
    (bsc#1104427 ).

  - rdma/hns: Bugfix for init hem table (bsc#1104427).

  - rdma/hns: Bugfix for rq record db for kernel
    (bsc#1104427 ).

  - rdma/hns: Check return value of kzalloc (bsc#1104427 ).

  - rdma/hns: Configure BT BA and BT attribute for the
    contexts in hip08 (bsc#1104427).

  - rdma/hns: Configure fence attribute in hip08 RoCE
    (bsc#1104427 ).

  - rdma/hns: Configure mac&gid and user access region for
    hip08 RoCE driver (bsc#1104427).

  - rdma/hns: Configure sgid type for hip08 RoCE
    (bsc#1104427 ).

  - rdma/hns: Configure the MTPT in hip08 (bsc#1104427).

  - rdma/hns: Configure TRRL field in hip08 RoCE device
    (bsc#1104427 ).

  - rdma/hns: Create gsi qp in hip08 (bsc#1104427).

  - rdma/hns: Delete the unnecessary initializing enum to
    zero (bsc#1104427).

  - rdma/hns: Do not unregister a callback we didn't
    register (bsc#1104427).

  - rdma/hns: Drop local zgid in favor of core defined
    variable (bsc#1104427).

  - rdma/hns: Enable inner_pa_vld filed of mpt (bsc#1104427
    ).

  - rdma/hns: Enable the cqe field of sqwqe of RC
    (bsc#1104427 ).

  - rdma/hns: ensure for-loop actually iterates and free's
    buffers (bsc#1104427).

  - rdma/hns: Fill sq wqe context of ud type in hip08
    (bsc#1104427 ).

  - rdma/hns: Filter for zero length of sge in hip08 kernel
    mode (bsc#1104427).

  - rdma/hns: Fix a bug with modifying mac address
    (bsc#1104427 ).

  - rdma/hns: Fix a couple misspellings (bsc#1104427).

  - rdma/hns: Fix calltrace for sleeping in atomic
    (bsc#1104427 ).

  - rdma/hns: Fix cqn type and init resp (bsc#1104427).

  - rdma/hns: Fix cq record doorbell enable in kernel
    (bsc#1104427 ).

  - rdma/hns: Fix endian problems around imm_data and rkey
    (bsc#1104427).

  - rdma/hns: Fix inconsistent warning (bsc#1104427).

  - rdma/hns: Fix init resp when alloc ucontext (bsc#1104427
    ).

  - rdma/hns: Fix misplaced call to
    hns_roce_cleanup_hem_table (bsc#1104427).

  - rdma/hns: Fix QP state judgement before receiving work
    requests (bsc#1104427).

  - rdma/hns: Fix QP state judgement before sending work
    requests (bsc#1104427).

  - rdma/hns: fix spelling mistake: 'Reseved' -> 'Reserved'
    (bsc#1104427).

  - rdma/hns: Fix the bug with NULL pointer (bsc#1104427 ).

  - rdma/hns: Fix the bug with rq sge (bsc#1104427).

  - rdma/hns: Fix the endian problem for hns (bsc#1104427 ).

  - rdma/hns: Fix the illegal memory operation when cross
    page (bsc#1104427).

  - rdma/hns: Fix the issue of IOVA not page continuous in
    hip08 (bsc#1104427).

  - rdma/hns: Fix the qp context state diagram (bsc#1104427
    ).

  - rdma/hns: Generate gid type of RoCEv2 (bsc#1104427).

  - rdma/hns: Get rid of page operation after
    dma_alloc_coherent (bsc#1104427).

  - rdma/hns: Get rid of virt_to_page and vmap calls after
    dma_alloc_coherent (bsc#1104427).

  - rdma/hns: Implement the disassociate_ucontext API
    (bsc#1104427 ).

  - rdma/hns: Increase checking CMQ status timeout value
    (bsc#1104427).

  - rdma/hns: Initialize the PCI device for hip08 RoCE
    (bsc#1104427 ).

  - rdma/hns: Intercept illegal RDMA operation when use
    inline data (bsc#1104427).

  - rdma/hns: Load the RoCE dirver automatically
    (bsc#1104427 ).

  - rdma/hns: make various function static, fixes warnings
    (bsc#1104427).

  - rdma/hns: Modify assignment device variable to support
    both PCI device and platform device (bsc#1104427).

  - rdma/hns: Modify the usage of cmd_sn in hip08
    (bsc#1104427 ).

  - rdma/hns: Modify the value with rd&dest_rd of qp_attr
    (bsc#1104427).

  - rdma/hns: Modify uar allocation algorithm to avoid
    bitmap exhaust (bsc#1104427).

  - rdma/hns: Move priv in order to add multiple hns_roce
    support (bsc#1104427).

  - rdma/hns: Move the location for initializing tmp_len
    (bsc#1104427).

  - rdma/hns: Not support qp transition from reset to reset
    for hip06 (bsc#1104427).

  - rdma/hns: Only assign dest_qp if IB_QP_DEST_QPN bit is
    set (bsc#1104427).

  - rdma/hns: Only assign dqpn if IB_QP_PATH_DEST_QPN bit is
    set (bsc#1104427).

  - rdma/hns: Only assign mtu if IB_QP_PATH_MTU bit is set
    (bsc#1104427).

  - rdma/hns: Refactor code for readability (bsc#1104427 ).

  - rdma/hns: Refactor eq code for hip06 (bsc#1104427).

  - rdma/hns: remove redundant assignment to variable j
    (bsc#1104427 ).

  - rdma/hns: Remove some unnecessary attr_mask judgement
    (bsc#1104427).

  - rdma/hns: Remove unnecessary operator (bsc#1104427).

  - rdma/hns: Remove unnecessary platform_get_resource()
    error check (bsc#1104427).

  - rdma/hns: Rename the idx field of db (bsc#1104427).

  - rdma/hns: Replace condition statement using hardware
    version information (bsc#1104427).

  - rdma/hns: Replace __raw_write*(cpu_to_le*()) with LE
    write*() (bsc#1104427).

  - rdma/hns: return 0 rather than return a garbage status
    value (bsc#1104427).

  - rdma/hns_roce: Do not check return value of
    zap_vma_ptes() (bsc#1104427).

  - rdma/hns: Set access flags of hip08 RoCE (bsc#1104427 ).

  - rdma/hns: Set desc_dma_addr for zero when free cmq desc
    (bsc#1104427).

  - rdma/hns: Set NULL for __internal_mr (bsc#1104427).

  - rdma/hns: Set rdma_ah_attr type for querying qp
    (bsc#1104427 ).

  - rdma/hns: Set se attribute of sqwqe in hip08
    (bsc#1104427 ).

  - rdma/hns: Set sq_cur_sge_blk_addr field in QPC in hip08
    (bsc#1104427).

  - rdma/hns: Set the guid for hip08 RoCE device
    (bsc#1104427 ).

  - rdma/hns: Set the owner field of SQWQE in hip08 RoCE
    (bsc#1104427).

  - rdma/hns: Split CQE from MTT in hip08 (bsc#1104427).

  - rdma/hns: Split hw v1 driver from hns roce driver
    (bsc#1104427 ).

  - rdma/hns: Submit bad wr (bsc#1104427).

  - rdma/hns: Support cq record doorbell for kernel space
    (bsc#1104427).

  - rdma/hns: Support cq record doorbell for the user space
    (bsc#1104427).

  - rdma/hns: Support multi hop addressing for PBL in hip08
    (bsc#1104427).

  - rdma/hns: Support rq record doorbell for kernel space
    (bsc#1104427).

  - rdma/hns: Support rq record doorbell for the user space
    (bsc#1104427).

  - rdma/hns: Support WQE/CQE/PBL page size configurable
    feature in hip08 (bsc#1104427).

  - rdma/hns: Unify the calculation for hem index in hip08
    (bsc#1104427).

  - rdma/hns: Update assignment method for owner field of
    send wqe (bsc#1104427).

  - rdma/hns: Update calculation of irrl_ba field for hip08
    (bsc#1104427).

  - rdma/hns: Update convert function of endian format
    (bsc#1104427 ).

  - rdma/hns: Update the interfaces for MTT/CQE multi hop
    addressing in hip08 (bsc#1104427).

  - rdma/hns: Update the IRRL table chunk size in hip08
    (bsc#1104427 ).

  - rdma/hns: Update the PD&CQE&MTT specification in hip08
    (bsc#1104427).

  - rdma/hns: Update the usage of ack timeout in hip08
    (bsc#1104427 ).

  - rdma/hns: Update the usage of sr_max and rr_max field
    (bsc#1104427).

  - rdma/hns: Update the verbs of polling for completion
    (bsc#1104427).

  - rdma/hns: Use free_pages function instead of free_page
    (bsc#1104427).

  - rdma/hns: Use structs to describe the uABI instead of
    opencoding (bsc#1104427).

  - rdma/qedr: Fix NULL pointer dereference when running
    over iWARP without RDMA-CM (bsc#1086314).

  - rdma/qedr: fix spelling mistake: 'adrresses' ->
    'addresses' (bsc#1086314).

  - rdma/qedr: fix spelling mistake: 'failes' -> 'fails'
    (bsc#1086314).

  - reiserfs: fix buffer overflow with long warning messages
    (bsc#1101847).

  -
    reiserfs-fix-buffer-overflow-with-long-warning-messa.pat
    ch: Silence bogus compiler warning about unused result
    of strscpy().

  - s390/dasd: configurable IFCC handling (bsc#1097808).

  - sched/smt: Update sched_smt_present at runtime
    (bsc#1089343).

  - scsi: mpt3sas: Add an I/O barrier (bsc#1086906,).

  - scsi: mpt3sas: Added support for SAS Device Discovery
    Error Event (bsc#1086906,).

  - scsi: mpt3sas: Add PCI device ID for Andromeda
    (bsc#1086906,).

  - scsi: mpt3sas: Allow processing of events during driver
    unload (bsc#1086906,).

  - scsi: mpt3sas: As per MPI-spec, use combined reply queue
    for SAS3.5 controllers when HBA supports more than 16
    MSI-x vectors (bsc#1086906,).

  - scsi: mpt3sas: Bug fix for big endian systems
    (bsc#1086906,).

  - scsi: mpt3sas: Cache enclosure pages during enclosure
    add (bsc#1086906,).

  - scsi: mpt3sas: clarify mmio pointer types
    (bsc#1086906,).

  - scsi: mpt3sas: Configure reply post queue depth, DMA and
    sgl tablesize (bsc#1086906,).

  - scsi: mpt3sas: Do not abort I/Os issued to NVMe drives
    while processing Async Broadcast primitive event
    (bsc#1086906,).

  - scsi: mpt3sas: Do not access the structure after
    decrementing it's instance reference count
    (bsc#1086906,).

  - scsi: mpt3sas: Do not mark fw_event workqueue as
    WQ_MEM_RECLAIM (bsc#1086906,).

  - scsi: mpt3sas: Enhanced handling of Sense Buffer
    (bsc#1086906,).

  - scsi: mpt3sas: Fix, False timeout prints for ioctl and
    other internal commands during controller reset
    (bsc#1086906,).

  - scsi: mpt3sas: fix possible memory leak (bsc#1086906,).

  - scsi: mpt3sas: fix spelling mistake: 'disbale' ->
    'disable' (bsc#1086906,).

  - scsi: mpt3sas: For NVME device, issue a protocol level
    reset (bsc#1086906,).

  - scsi: mpt3sas: Incorrect command status was set/marked
    as not used (bsc#1086906,).

  - scsi: mpt3sas: Increase event log buffer to support 24
    port HBA's (bsc#1086906,).

  - scsi: mpt3sas: Introduce API to get BAR0 mapped buffer
    address (bsc#1086906,).

  - scsi: mpt3sas: Introduce Base function for cloning
    (bsc#1086906,).

  - scsi: mpt3sas: Introduce function to clone mpi reply
    (bsc#1086906,).

  - scsi: mpt3sas: Introduce function to clone mpi request
    (bsc#1086906,).

  - scsi: mpt3sas: Lockless access for chain buffers
    (bsc#1086906,).

  - scsi: mpt3sas: Optimize I/O memory consumption in driver
    (bsc#1086906,).

  - scsi: mpt3sas: Pre-allocate RDPQ Array at driver boot
    time (bsc#1086906,).

  - scsi: mpt3sas: Replace PCI pool old API (bsc#1081917). -
    Refresh
    patches.drivers/scsi-mpt3sas-SGL-to-PRP-Translation-for-
    I-Os-to-NVMe.patch.

  - scsi: mpt3sas: Report Firmware Package Version from HBA
    Driver (bsc#1086906,).

  - scsi: mpt3sas: Update driver version '25.100.00.00'
    (bsc#1086906,).

  - scsi: mpt3sas: Update driver version '26.100.00.00'
    (bsc#1086906,).

  - scsi: mpt3sas: Update MPI Headers (bsc#1086906,).

  - scsi: qedf: Add additional checks when restarting an
    rport due to ABTS timeout (bsc#1086317).

  - scsi: qedf: Add check for offload before flushing I/Os
    for target (bsc#1086317).

  - scsi: qedf: Add dcbx_not_wait module parameter so we
    won't wait for DCBX convergence to start discovery
    (bsc#1086317).

  - scsi: qedf: Add missing skb frees in error path
    (bsc#1086317).

  - scsi: qedf: Add more defensive checks for concurrent
    error conditions (bsc#1086317).

  - scsi: qedf: Add task id to kref_get_unless_zero() debug
    messages when flushing requests (bsc#1086317).

  - scsi: qedf: Check if link is already up when receiving a
    link up event from qed (bsc#1086317).

  - scsi: qedf: fix LTO-enabled build (bsc#1086317).

  - scsi: qedf: Fix VLAN display when printing sent FIP
    frames (bsc#1086317).

  - scsi: qedf: Honor default_prio module parameter even if
    DCBX does not converge (bsc#1086317).

  - scsi: qedf: Honor priority from DCBX FCoE App tag
    (bsc#1086317).

  - scsi: qedf: If qed fails to enable MSI-X fail PCI probe
    (bsc#1086317).

  - scsi: qedf: Improve firmware debug dump handling
    (bsc#1086317).

  - scsi: qedf: Increase the number of default FIP VLAN
    request retries to 60 (bsc#1086317).

  - scsi: qedf: Release RRQ reference correctly when RRQ
    command times out (bsc#1086317).

  - scsi: qedf: remove redundant initialization of 'fcport'
    (bsc#1086317).

  - scsi: qedf: Remove setting DCBX pending during soft
    context reset (bsc#1086317).

  - scsi: qedf: Return request as DID_NO_CONNECT if MSI-X is
    not enabled (bsc#1086317).

  - scsi: qedf: Sanity check FCoE/FIP priority value to make
    sure it's between 0 and 7 (bsc#1086317).

  - scsi: qedf: Send the driver state to MFW (bsc#1086317).

  - scsi: qedf: Set the UNLOADING flag when removing a vport
    (bsc#1086317).

  - scsi: qedf: Synchronize rport restarts when multiple ELS
    commands time out (bsc#1086317).

  - scsi: qedf: Update copyright for 2018 (bsc#1086317).

  - scsi: qedf: Update version number to 8.33.16.20
    (bsc#1086317).

  - scsi: qedf: use correct strncpy() size (bsc#1086317).

  - scsi: qedi: fix building with LTO (bsc#1086315).

  - scsi: qedi: fix build regression (bsc#1086315).

  - scsi: qedi: Fix kernel crash during port toggle
    (bsc#1086315).

  - scsi: qedi: Send driver state to MFW (bsc#1086315).

  - scsi: qla2xxx: correctly shift host byte (bsc#1086327,).

  - scsi: qla2xxx: Correct setting of
    SAM_STAT_CHECK_CONDITION (bsc#1086327,).

  - scsi: qla2xxx: Fix crash on qla2x00_mailbox_command
    (bsc#1086327,).

  - scsi: qla2xxx: Fix Inquiry command being dropped in
    Target mode (bsc#1086327,).

  - scsi: qla2xxx: Fix race condition between iocb timeout
    and initialisation (bsc#1086327,).

  - scsi: qla2xxx: Fix Rport and session state getting out
    of sync (bsc#1086327,).

  - scsi: qla2xxx: Fix sending ADISC command for login
    (bsc#1086327,).

  - scsi: qla2xxx: Fix setting lower transfer speed if GPSC
    fails (bsc#1086327,).

  - scsi: qla2xxx: Fix TMF and Multi-Queue config
    (bsc#1086327,).

  - scsi: qla2xxx: Move GPSC and GFPNID out of session
    management (bsc#1086327,).

  - scsi: qla2xxx: Prevent relogin loop by removing stale
    code (bsc#1086327,).

  - scsi: qla2xxx: Reduce redundant ADISC command for RSCNs
    (bsc#1086327,).

  - scsi: qla2xxx: remove irq save in qla2x00_poll()
    (bsc#1086327,).

  - scsi: qla2xxx: Remove stale debug value for login_retry
    flag (bsc#1086327,).

  - scsi: qla2xxx: Update driver version to 10.00.00.07-k
    (bsc#1086327,).

  - scsi: qla2xxx: Use predefined get_datalen_for_atio()
    inline function (bsc#1086327,).

  - scsi: qla4xxx: Move an array from a .h into a .c file
    (bsc#1086331).

  - scsi: qla4xxx: Remove unused symbols (bsc#1086331).

  - scsi: qla4xxx: skip error recovery in case of register
    disconnect (bsc#1086331).

  - scsi: qla4xxx: Use dma_pool_zalloc() (bsc#1086331).

  - scsi: qla4xxx: Use zeroing allocator rather than
    allocator/memset (bsc#1086331).

  - selftests/powerpc: Fix core-pkey for default execute
    permission change (bsc#1097577).

  - selftests/powerpc: Fix ptrace-pkey for default execute
    permission change (bsc#1097577).

  - supported.conf: add drivers/md/dm-writecache

  - supported.conf: added hns3 modules

  - supported.conf: added hns-roce-hw-v1 and hns-roce-hw-v2

  - supported.conf: Enable HiSi v3 SAS adapter ()

  - tcp_rbd depends on BLK_DEV_RBD ().

  - typec: tcpm: fusb302: Resolve out of order messaging
    events (bsc#1087092).

  - udf: Detect incorrect directory size (bsc#1101891).

  - udf: Provide saner default for invalid uid / gid
    (bsc#1101890).

  - vfs: add the sb_start_intwrite_trylock() helper
    (bsc#1101841).

  - x86/apic: Ignore secondary threads if nosmt=force
    (bsc#1089343).

  - x86/CPU/AMD: Do not check CPUID max ext level before
    parsing SMP info (bsc#1089343).

  - x86/cpu/AMD: Evaluate smp_num_siblings early
    (bsc#1089343).

  - x86/CPU/AMD: Move TOPOEXT reenablement before reading
    smp_num_siblings (bsc#1089343).

  - x86/cpu/AMD: Remove the pointless detect_ht() call
    (bsc#1089343).

  - x86/cpu/common: Provide detect_ht_early() (bsc#1089343).

  - x86/cpu/intel: Evaluate smp_num_siblings early
    (bsc#1089343).

  - x86/cpu: Remove the pointless CPU printout
    (bsc#1089343).

  - x86/cpu/topology: Provide
    detect_extended_topology_early() (bsc#1089343).

  - x86/KVM/VMX: Add module argument for L1TF mitigation.

  - x86/smp: Provide topology_is_primary_thread()
    (bsc#1089343).

  - x86/topology: Provide topology_smt_supported()
    (bsc#1089343).

  - x86/xen: init %gs very early to avoid page faults with
    stack protector (bnc#1104777).

  - xen-netback: fix input validation in
    xenvif_set_hash_mapping() (bnc#1103277).

  - xen/netfront: do not cache skb_shinfo() (bnc#1065600).

  - xfs: catch inode allocation state mismatch corruption
    (bsc#1104211).

  - xfs: prevent creating negative-sized file via
    INSERT_RANGE (bsc#1101833)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104777"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10877");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.16.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
