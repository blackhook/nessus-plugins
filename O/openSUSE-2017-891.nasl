#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-891.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102333);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10810", "CVE-2017-11473", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-891)");
  script_summary(english:"Check for the openSUSE-2017-891 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.79 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-7542: The ip6_find_1stfragopt function in
    net/ipv6/output_core.c in the Linux kernel allowed local
    users to cause a denial of service (integer overflow and
    infinite loop) by leveraging the ability to open a raw
    socket (bnc#1049882).

  - CVE-2017-11473: Buffer overflow in the
    mp_override_legacy_irq() function in
    arch/x86/kernel/acpi/boot.c in the Linux kernel allowed
    local users to gain privileges via a crafted ACPI table
    (bnc#1049603).

  - CVE-2017-7533: A bug in inotify code allowed local users
    to escalate privilege (bnc#1049483).

  - CVE-2017-7541: The brcmf_cfg80211_mgmt_tx function in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg8021
    1.c in the Linux kernel allowed local users to cause a
    denial of service (buffer overflow and system crash) or
    possibly gain privileges via a crafted NL80211_CMD_FRAME
    Netlink packet (bnc#1049645).

  - CVE-2017-10810: Memory leak in the
    virtio_gpu_object_create function in
    drivers/gpu/drm/virtio/virtgpu_object.c in the Linux
    kernel allowed attackers to cause a denial of service
    (memory consumption) by triggering object-initialization
    failures (bnc#1047277).

The following non-security bugs were fixed :

  - acpi / processor: Avoid reserving IO regions too early
    (bsc#1051478).

  - af_key: Add lock to key dump (bsc#1047653).

  - af_key: Fix slab-out-of-bounds in pfkey_compile_policy
    (bsc#1047354).

  - alsa: fm801: Initialize chip after IRQ handler is
    registered (bsc#1031717).

  - alsa: hda - Fix endless loop of codec configure
    (bsc#1031717).

  - alsa: hda - set input_path bitmap to zero after moving
    it to new place (bsc#1031717).

  - b43: Add missing MODULE_FIRMWARE() (bsc#1037344).

  - bcache: force trigger gc (bsc#1038078).

  - bcache: only recovery I/O error for writethrough mode
    (bsc#1043652).

  - bdi: Fix use-after-free in wb_congested_put()
    (bsc#1040307).

  - blacklist 2400fd822f46 powerpc/asm: Mark cr0 as
    clobbered in mftb()

  - blacklist.conf :

  - blacklist.conf: 1151f838cb62 is high-risk and we're not
    aware of any systems that might need it in SP2.

  - blacklist.conf: 8b8642af15ed not a supported driver

  - blacklist.conf: 9eeacd3a2f17 not a bug fix (bnc#1050061)

  - blacklist.conf: add inapplicable commits for wifi
    (bsc#1031717)

  - blacklist.conf: add unapplicable/cosmetic iwlwifi fixes
    (bsc#1031717).

  - blacklist.conf: add unapplicable drm fixes
    (bsc#1031717).

  - blacklist.conf: Blacklist 4e201566402c ('genirq/msi:
    Drop artificial PCI dependency') (bsc#1051478) This
    commit just removes an include and does not fix a real
    issue.

  - blacklist.conf: blacklist 7b73305160f1, unneeded cleanup

  - blacklist.conf: Blacklist aa2369f11ff7 ('mm/gup.c: fix
    access_ok() argument type') (bsc#1051478) Fixes only a
    compile-warning.

  - blacklist.conf: Blacklist c133c7615751 ('x86/nmi: Fix
    timeout test in test_nmi_ipi()') It only fixes a
    self-test (bsc#1051478).

  - blacklist.conf: Blacklist c9525a3fab63 ('x86/watchdog:
    Fix Kconfig help text file path reference to lockup
    watchdog documentation') Updates only kconfig help-text
    (bsc#1051478).

  - blacklist.conf: Blacklist e80e7edc55ba ('PCI/MSI:
    Initialize MSI capability for all architectures') This
    only fixes machines not supported by our kernels.

  - blacklist.conf: build time cleanup our kernel compiles.
    No need to shut up warnings nobody looks at

  - blacklist.conf: cleanup, no bugs fixed

  - blacklist.conf: cxgb4 commit does not fit for SP2

  - blacklist.conf: da0510c47519fe0999cffe316e1d370e29f952be
    # FRV not applicable to SLE

  - blacklist.conf: Do not need 55d728a40d36, we do it
    differently in SLE

  - blacklist.conf: kABI breakage This touches struct
    device.

  - blacklist.conf: lp8788 is not compiled

  - blacklist.conf: unneeded Fixing debug statements on BE
    systems for IrDA

  - blkfront: add uevent for size change (bnc#1036632).

  - block: Allow bdi re-registration (bsc#1040307).

  - block: Fix front merge check (bsc#1051239).

  - block: Make del_gendisk() safer for disks without queues
    (bsc#1040307).

  - block: Move bdi_unregister() to del_gendisk()
    (bsc#1040307).

  - brcmfmac: Fix glom_skb leak in brcmf_sdiod_recv_chain
    (bsc#1031717).

  - btrfs: add cond_resched to btrfs_qgroup_trace_leaf_items
    (bsc#1028286).

  - btrfs: Add WARN_ON for qgroup reserved underflow
    (bsc#1031515).

  - btrfs: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - btrfs: fix lockup in find_free_extent with read-only
    block groups (bsc#1046682).

  - btrfs: incremental send, fix invalid path for link
    commands (bsc#1051479).

  - btrfs: incremental send, fix invalid path for unlink
    commands (bsc#1051479).

  - btrfs: resume qgroup rescan on rw remount (bsc#1047152).

  - btrfs: send, fix invalid path after renaming and linking
    file (bsc#1051479).

  - cpuidle: dt: Add missing 'of_node_put()' (bnc#1022476).

  - crypto: s5p-sss - fix incorrect usage of scatterlists
    api (bsc#1048317).

  - cx82310_eth: use skb_cow_head() to deal with cloned skbs
    (bsc# 1045154).

  - cxl: Unlock on error in probe (bsc#1034762, Pending SUSE
    Kernel Fixes).

  - dentry name snapshots (bsc#1049483).

  - dm: fix second blk_delay_queue() parameter to be in msec
    units not (bsc#1047670).

  - drivers: hv: Fix the bug in generating the guest ID
    (fate#320485).

  - drivers: hv: util: Fix a typo (fate#320485).

  - drivers: hv: vmbus: Get the current time from the
    current clocksource (fate#320485, bnc#1044112,
    bnc#1042778, bnc#1029693).

  - drivers: hv: vmbus: Increase the time between retries in
    vmbus_post_msg() (fate#320485, bnc#1044112).

  - drivers: hv: vmbus: Move the code to signal end of
    message (fate#320485).

  - drivers: hv: vmbus: Move the definition of
    generate_guest_id() (fate#320485).

  - drivers: hv: vmbus: Move the definition of
    hv_x64_msr_hypercall_contents (fate#320485).

  - drivers: hv: vmbus: Restructure the clockevents code
    (fate#320485).

  - drm/amdgpu: Fix overflow of watermark calcs at > 4k
    resolutions (bsc#1031717).

  - drm/bochs: Implement nomodeset (bsc#1047096).

  - drm/i915/fbdev: Stop repeating tile configuration on
    stagnation (bsc#1031717).

  - drm/i915: Fix scaler init during CRTC HW state readout
    (bsc#1031717).

  - drm/virtio: do not leak bo on drm_gem_object_init
    failure (bsc#1047277).

  - drm/vmwgfx: Fix large topology crash (bsc#1048155).

  - drm/vmwgfx: Support topology greater than texture size
    (bsc#1048155).

  - drop patches; obsoleted by 'scsi: Add
    STARGET_CREATE_REMOVE state'

  - efi/libstub: Skip GOP with PIXEL_BLT_ONLY format
    (bnc#974215).

  - ext2: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - ext4: avoid unnecessary stalls in ext4_evict_inode()
    (bsc#1049486).

  - ext4: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - ext4: handle the rest of ext4_mb_load_buddy() ENOMEM
    errors (bsc#1012829).

  - Fix kABI breakage by KVM CVE fix (bsc#1045922).

  - fs/fcntl: f_setown, avoid undefined behaviour
    (bnc#1006180).

  - gcov: add support for gcc version >= 6 (bsc#1051663).

  - gcov: support GCC 7.1 (bsc#1051663).

  - gfs2: fix flock panic issue (bsc#1012829).

  - hrtimer: Catch invalid clockids again (bsc#1047651).

  - hrtimer: Revert CLOCK_MONOTONIC_RAW support
    (bsc#1047651).

  - hv_utils: drop .getcrosststamp() support from PTP driver
    (fate#320485, bnc#1044112, bnc#1042778, bnc#1029693).

  - hv_utils: fix TimeSync work on pre-TimeSync-v4 hosts
    (fate#320485, bnc#1044112, bnc#1042778, bnc#1029693).

  - hv_util: switch to using timespec64 (fate#320485).

  - i2c: designware-baytrail: fix potential NULL pointer
    dereference on dev (bsc#1011913).

  - i40e: add hw struct local variable (bsc#1039915).

  - i40e: add private flag to control source pruning
    (bsc#1034075).

  - i40e: add VSI info to macaddr messages (bsc#1039915).

  - i40e: avoid looping to check whether we're in VLAN mode
    (bsc#1039915).

  - i40e: avoid O(n^2) loop when deleting all filters
    (bsc#1039915).

  - i40e: delete filter after adding its replacement when
    converting (bsc#1039915).

  - i40e: do not add broadcast filter for VFs (bsc#1039915).

  - i40e: do not allow i40e_vsi_(add|kill)_vlan to operate
    when VID<1 (bsc#1039915).

  - i40e: drop is_vf and is_netdev fields in struct
    i40e_mac_filter (bsc#1039915).

  - i40e: enable VSI broadcast promiscuous mode instead of
    adding broadcast filter (bsc#1039915).

  - i40e: factor out addition/deletion of VLAN per each MAC
    address (bsc#1039915).

  - i40e: fix MAC filters when removing VLANs (bsc#1039915).

  - i40e: fold the i40e_is_vsi_in_vlan check into
    i40e_put_mac_in_vlan (bsc#1039915).

  - i40e: implement __i40e_del_filter and use where
    applicable (bsc#1039915).

  - i40e: make use of __dev_uc_sync and __dev_mc_sync
    (bsc#1039915).

  - i40e: move all updates for VLAN mode into
    i40e_sync_vsi_filters (bsc#1039915).

  - i40e: move i40e_put_mac_in_vlan and
    i40e_del_mac_all_vlan (bsc#1039915).

  - i40e: no need to check is_vsi_in_vlan before calling
    i40e_del_mac_all_vlan (bsc#1039915).

  - i40e: properly cleanup on allocation failure in
    i40e_sync_vsi_filters (bsc#1039915).

  - i40e: recalculate vsi->active_filters from hash contents
    (bsc#1039915).

  - i40e: refactor i40e_put_mac_in_vlan to avoid changing
    f->vlan (bsc#1039915).

  - i40e: refactor i40e_update_filter_state to avoid passing
    aq_err (bsc#1039915).

  - i40e: refactor Rx filter handling (bsc#1039915).

  - i40e: Removal of workaround for simple MAC address
    filter deletion (bsc#1039915).

  - i40e: remove code to handle dev_addr specially
    (bsc#1039915).

  - i40e: removed unreachable code (bsc#1039915).

  - i40e: remove duplicate add/delete adminq command code
    for filters (bsc#1039915).

  - i40e: remove second check of VLAN_N_VID in
    i40e_vlan_rx_add_vid (bsc#1039915).

  - i40e: rename i40e_put_mac_in_vlan and
    i40e_del_mac_all_vlan (bsc#1039915).

  - i40e: restore workaround for removing default MAC filter
    (bsc#1039915).

  - i40e: set broadcast promiscuous mode for each active
    VLAN (bsc#1039915).

  - i40e: store MAC/VLAN filters in a hash with the MAC
    Address as key (bsc#1039915).

  - i40e: use (add|rm)_vlan_all_mac helper functions when
    changing PVID (bsc#1039915).

  - i40e: when adding or removing MAC filters, correctly
    handle VLANs (bsc#1039915).

  - i40e: When searching all MAC/VLAN filters, ignore
    removed filters (bsc#1039915).

  - i40e: write HENA for VFs (bsc#1039915).

  - iio: hid-sensor: fix return of -EINVAL on invalid values
    in ret or value (bsc#1031717).

  - Input: gpio-keys - fix check for disabling unsupported
    keys (bsc#1031717).

  - introduce the walk_process_tree() helper (bnc#1022476).

  - ipv4: Should use consistent conditional judgement for ip
    fragment in __ip_append_data and ip_finish_output
    (bsc#1041958).

  - ipv6: Should use consistent conditional judgement for
    ip6 fragment between __ip6_append_data and
    ip6_finish_output (bsc#1041958).

  - iwlwifi: mvm: compare full command ID (FATE#321353,
    FATE#323335).

  - iwlwifi: mvm: reset the fw_dump_desc pointer after
    ASSERT (bsc#1031717).

  - iwlwifi: mvm: synchronize firmware DMA paging memory
    (FATE#321353, FATE#323335).

  - iwlwifi: mvm: unconditionally stop device after init
    (bsc#1031717).

  - iwlwifi: mvm: unmap the paging memory before freeing it
    (FATE#321353, FATE#323335).

  - iwlwifi: pcie: fix command completion name debug
    (bsc#1031717).

  - kABI-fix for 'x86/panic: replace smp_send_stop() with
    kdump friendly version in panic path' (bsc#1051478).

  - kABI: protect lwtunnel include in ip6_route.h (kabi).

  - kABI: protect struct iscsi_tpg_attrib (kabi).

  - kABI: protect struct tpm_chip (kabi).

  - kABI: protect struct xfrm_dst (kabi).

  - kABI: protect struct xfrm_dst (kabi).

  - kvm: nVMX: fix msr bitmaps to prevent L2 from accessing
    L0 x2APIC (bsc#1051478).

  - kvm: nVMX: Fix nested_vmx_check_msr_bitmap_controls
    (bsc#1051478).

  - kvm: nVMX: Fix nested VPID vmx exec control
    (bsc#1051478).

  - kvm: x86: avoid simultaneous queueing of both IRQ and
    SMI (bsc#1051478).

  - mac80211_hwsim: Replace bogus hrtimer clockid
    (bsc#1047651).

  - md: fix sleep in atomic (bsc#1040351).

  - mm: adaptive hash table scaling (bnc#1036303).

  - mm-adaptive-hash-table-scaling-v5 (bnc#1036303).

  - mm: call page_ext_init() after all struct pages are
    initialized (VM Debugging Functionality, bsc#1047048).

  - mm: drop HASH_ADAPT (bnc#1036303).

  - mm: fix classzone_idx underflow in shrink_zones() (VM
    Functionality, bsc#1042314).

  - mm: make PR_SET_THP_DISABLE immediately active
    (bnc#1048891).

  - More Git-commit header fixups No functional change
    intended.

  - mwifiex: do not update MCS set from hostapd
    (bsc#1031717).

  - net: account for current skb length when deciding about
    UFO (bsc#1041958).

  - net: ena: add hardware hints capability to the driver
    (bsc#1047121).

  - net: ena: add missing return when
    ena_com_get_io_handlers() fails (bsc#1047121).

  - net: ena: add missing unmap bars on device removal
    (bsc#1047121).

  - net: ena: add reset reason for each device FLR
    (bsc#1047121).

  - net: ena: add support for out of order rx buffers refill
    (bsc#1047121).

  - net: ena: allow the driver to work with small number of
    msix vectors (bsc#1047121).

  - net: ena: bug fix in lost tx packets detection mechanism
    (bsc#1047121).

  - net: ena: change return value for unsupported features
    unsupported return value (bsc#1047121).

  - net: ena: change sizeof() argument to be the type
    pointer (bsc#1047121).

  - net: ena: disable admin msix while working in polling
    mode (bsc#1047121).

  - net: ena: fix bug that might cause hang after
    consecutive open/close interface (bsc#1047121).

  - net: ena: fix race condition between submit and
    completion admin command (bsc#1047121).

  - net: ena: fix rare uncompleted admin command false alarm
    (bsc#1047121).

  - net: ena: fix theoretical Rx hang on low memory systems
    (bsc#1047121).

  - net: ena: separate skb allocation to dedicated function
    (bsc#1047121).

  - net: ena: update driver's rx drop statistics
    (bsc#1047121).

  - net: ena: update ena driver to version 1.1.7
    (bsc#1047121).

  - net: ena: update ena driver to version 1.2.0
    (bsc#1047121).

  - net: ena: use lower_32_bits()/upper_32_bits() to split
    dma address (bsc#1047121).

  - net: ena: use napi_schedule_irqoff when possible
    (bsc#1047121).

  - net: handle NAPI_GRO_FREE_STOLEN_HEAD case also in
    napi_frags_finish() (bsc#1042286).

  - net/mlx5: Fix driver load error flow when firmware is
    stuck (git-fixes).

  - net: phy: Do not perform software reset for Generic PHY
    (bsc#1042286).

  - nfs: Cache aggressively when file is open for writing
    (bsc#1033587).

  - nfs: Do not flush caches for a getattr that races with
    writeback (bsc#1033587).

  - nfs: invalidate file size when taking a lock
    (git-fixes).

  - nfs: only invalidate dentrys that are clearly invalid
    (bsc#1047118).

  - ocfs2: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - ocfs2: fix deadlock caused by recursive locking in xattr
    (bsc#1012829).

  - ocfs2: Make ocfs2_set_acl() static (bsc#1030552).

  - pci: Add Mellanox device IDs (bsc#1051478).

  - pci: Convert Mellanox broken INTx quirks to be for
    listed devices only (bsc#1051478).

  - pci: Correct PCI_STD_RESOURCE_END usage (bsc#1051478).

  - pci: dwc: dra7xx: Use RW1C for IRQSTATUS_MSI and
    IRQSTATUS_MAIN (bsc#1051478).

  - pci: dwc: Fix uninitialized variable in
    dw_handle_msi_irq() (bsc#1051478).

  - pci: Enable ECRC only if device supports it
    (bsc#1051478).

  - PCI / PM: Fix native PME handling during system
    suspend/resume (bsc#1051478).

  - pci: Support INTx masking on ConnectX-4 with firmware
    x.14.1100+ (bsc#1051478).

  - perf/x86: Fix spurious NMI with PEBS Load Latency event
    (bsc#1051478).

  - perf/x86/intel: Cure bogus unwind from PEBS entries
    (bsc#1051478).

  - perf/x86/intel: Fix PEBSv3 record drain (bsc#1051478).

  - platform/x86: ideapad-laptop: Add IdeaPad 310-15IKB to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add IdeaPad V310-15ISK to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add IdeaPad V510-15IKB to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Lenovo Yoga 910-13IKB
    to no_hw_rfkill dmi list (bsc#1051022).

  - platform/x86: ideapad-laptop: Add several models to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Y520-15IKBN to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Y700 15-ACZ to
    no_hw_rfkill DMI list (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Y720-15IKBN to
    no_hw_rfkill (bsc#1051022).

  - Pm / Hibernate: Fix scheduling while atomic during
    hibernation (bsc#1051059).

  - prctl: propagate has_child_subreaper flag to every
    descendant (bnc#1022476).

  - README.BRANCH: Add Oliver as openSUSE-42.2 branch
    co-maintainer

  - Refresh
    patches.kabi/Fix-kABI-breakage-by-KVM-CVE-fix.patch. Fix
    a stupid bug where the VCPU_REGS_TF shift was used as a
    mask.

  - reiserfs: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - Revert 'ACPI / video: Add force_native quirk for HP
    Pavilion dv6' (bsc#1031717).

  - Revert 'Add 'shutdown' to 'struct class'.' (kabi).

  - Revert 'kvm: x86: fix emulation of RSM and IRET
    instructions' (kabi).

  - Revert 'mm/list_lru.c: fix list_lru_count_node() to be
    race free' (kabi).

  - Revert 'powerpc/numa: Fix percpu allocations to be NUMA
    aware' (bsc#1048914).

  - Revert 'tpm: Issue a TPM2_Shutdown for TPM2 devices.'
    (kabi).

  - rpm/kernel-binary.spec.in: find-debuginfo.sh should not
    touch build-id This needs rpm-4.14+ (bsc#964063).

  - sched/core: Allow __sched_setscheduler() in interrupts
    when PI is not used (bnc#1022476).

  - sched/debug: Print the scheduler topology group mask
    (bnc#1022476).

  - sched/fair, cpumask: Export for_each_cpu_wrap()
    (bnc#1022476).

  - sched/fair: Fix O(nr_cgroups) in load balance path
    (bnc#1022476).

  - sched/fair: Use task_groups instead of leaf_cfs_rq_list
    to walk all cfs_rqs (bnc#1022476).

  - sched/topology: Add sched_group_capacity debugging
    (bnc#1022476).

  - sched/topology: Fix building of overlapping sched-groups
    (bnc#1022476).

  - sched/topology: Fix overlapping sched_group_capacity
    (bnc#1022476).

  - sched/topology: Move comment about asymmetric node
    setups (bnc#1022476).

  - sched/topology: Refactor function
    build_overlap_sched_groups() (bnc#1022476).

  - sched/topology: Remove FORCE_SD_OVERLAP (bnc#1022476).

  - sched/topology: Simplify build_overlap_sched_groups()
    (bnc#1022476).

  - sched/topology: Small cleanup (bnc#1022476).

  - sched/topology: Verify the first group matches the child
    domain (bnc#1022476).

  - scsi: Add STARGET_CREATE_REMOVE state to
    scsi_target_state (bsc#1013887).

  - scsi: bnx2i: missing error code in bnx2i_ep_connect()
    (bsc#1048221).

  - scsi: kABI fix for new state STARGET_CREATED_REMOVE
    (bsc#1013887).

  - scsi: storvsc: Workaround for virtual DVD SCSI version
    (fate#320485, bnc#1044636).

  - smsc75xx: use skb_cow_head() to deal with cloned skbs
    (bsc#1045154).

  - sr9700: use skb_cow_head() to deal with cloned skbs
    (bsc#1045154).

  - sysctl: do not print negative flag for proc_douintvec
    (bnc#1046985).

  - timers: Plug locking race vs. timer migration
    (bnc#1022476).

  - udf: Fix deadlock between writeback and udf_setsize()
    (bsc#1012829).

  - udf: Fix races with i_size changes during readpage
    (bsc#1012829).

  - x86/LDT: Print the real LDT base address (bsc#1051478).

  - x86/mce: Make timer handling more robust (bsc#1042422).

  - x86/panic: replace smp_send_stop() with kdump friendly
    version in panic path (bsc#1051478).

  - xen: allocate page for shared info page from low memory
    (bnc#1038616).

  - xen/balloon: do not online new memory initially
    (bnc#1028173).

  - xen: hold lock_device_hotplug throughout vcpu hotplug
    operations (bsc#1042422).

  - xen-netfront: Rework the fix for Rx stall during OOM and
    network stress (git-fixes).

  - xen/pvh*: Support > 32 VCPUs at domain restore
    (bnc#1045563).

  - xfrm: NULL dereference on allocation failure
    (bsc#1047343).

  - xfrm: Oops on error in pfkey_msg2xfrm_state()
    (bsc#1047653).

  - xfs: do not BUG() on mixed direct and mapped I/O
    (bsc#1050188).

  - xfs: Do not clear SGID when inheriting ACLs
    (bsc#1030552)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974215"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.79-18.23.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.79-18.23.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.79-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.79-18.23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
