#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-890.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102332);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11473", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-890)");
  script_summary(english:"Check for the openSUSE-2017-890 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.79 to receive various
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

The following non-security bugs were fixed :

  - ACPI / processor: Avoid reserving IO regions too early
    (bsc#1051478).

  - ALSA: fm801: Initialize chip after IRQ handler is
    registered (bsc#1031717).

  - Added sbitmap patch to blacklist.conf Add a patch
    'sbitmap: fix wakeup hang after sbq resize' to the
    blacklist.conf file because it is not needed in SLE 12
    SP2.

  - Btrfs: incremental send, fix invalid path for link
    commands (bsc#1051479).

  - Btrfs: incremental send, fix invalid path for unlink
    commands (bsc#1051479).

  - Btrfs: send, fix invalid path after renaming and linking
    file (bsc#1051479).

  - Delete
    patches.drivers/0004-iommu-amd-reduce-delay-waiting-for-
    command-buffer-space. Remove the patch because it caused
    problems for users. See bsc#1048348.

  - Drop patches; obsoleted by 'scsi: Add
    STARGET_CREATE_REMOVE state'

  - Fix kABI breakage by KVM CVE fix (bsc#1045922).

  - IB/rxe: Fix kernel panic from skb destructor
    (bsc#1049361).

  - KVM: nVMX: Fix nested VPID vmx exec control
    (bsc#1051478).

  - KVM: nVMX: fix msr bitmaps to prevent L2 from accessing
    L0 x2APIC (bsc#1051478).

  - KVM: x86: avoid simultaneous queueing of both IRQ and
    SMI (bsc#1051478).

  - NFS: Cache aggressively when file is open for writing
    (bsc#1033587).

  - NFS: Do not flush caches for a getattr that races with
    writeback (bsc#1033587).

  - NFS: invalidate file size when taking a lock
    (git-fixes).

  - PCI / PM: Fix native PME handling during system
    suspend/resume (bsc#1051478).

  - PCI: Add Mellanox device IDs (bsc#1051478).

  - PCI: Convert Mellanox broken INTx quirks to be for
    listed devices only (bsc#1051478).

  - PCI: Correct PCI_STD_RESOURCE_END usage (bsc#1051478).

  - PCI: Enable ECRC only if device supports it
    (bsc#1051478).

  - PCI: Support INTx masking on ConnectX-4 with firmware
    x.14.1100+ (bsc#1051478).

  - PCI: dwc: Fix uninitialized variable in
    dw_handle_msi_irq() (bsc#1051478).

  - PCI: dwc: dra7xx: Use RW1C for IRQSTATUS_MSI and
    IRQSTATUS_MAIN (bsc#1051478).

  - PM / Hibernate: Fix scheduling while atomic during
    hibernation (bsc#1051059).

  - RDMA/qedr: Prevent memory overrun in verbs' user
    responses (bsc#1022604 FATE#321747).

  - README.BRANCH: Add Oliver as openSUSE-42.3 branch
    co-maintainer

  - Refresh
    patches.kabi/Fix-kABI-breakage-by-KVM-CVE-fix.patch. Fix
    a stupid bug where the VCPU_REGS_TF shift was used as a
    mask.

  - Revert 'Add 'shutdown' to 'struct class'.' (kabi).

  - Revert 'mm/list_lru.c: fix list_lru_count_node() to be
    race free' (kabi).

  - Revert 'powerpc/numa: Fix percpu allocations to be NUMA
    aware' (bsc#1048914).

  - Revert 'powerpc/numa: Fix percpu allocations to be NUMA
    aware' (bsc#1048914).

  - Revert 'tpm: Issue a TPM2_Shutdown for TPM2 devices.'
    (kabi).

  - Update
    patches.drivers/0011-hpsa-remove-abort-handler.patch
    (bsc#1022600 fate#321928 bsc#1016119).

  - Update
    patches.fixes/xfs-refactor-log-record-unpack-and-data-pr
    ocessing.patch (bsc#1043598, bsc#1036215).

  - apply mainline tags to some hyperv patches

  - arm64: kernel: restrict /dev/mem read() calls to linear
    region (bsc#1046651).++ kernel-source.spec (revision
    3)%define patchversion 4.4.79Version: 4.4.79Release:
    <RELEASE>.g4dc78e3

  - arm64: mm: remove page_mapping check in
    __sync_icache_dcache (bsc#1040347).

  - blacklist 2400fd822f46 powerpc/asm: Mark cr0 as
    clobbered in mftb()

  - blacklist.conf: 9eeacd3a2f17 not a bug fix (bnc#1050061)

  - blacklist.conf: Blacklist 4e201566402c ('genirq/msi:
    Drop artificial PCI dependency') (bsc#1051478) This
    commit just removes an include and does not fix a real
    issue.

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

  - blacklist.conf: Do not need 55d728a40d36, we do it
    differently in SLE

  - blacklist.conf: add inapplicable commits for wifi
    (bsc#1031717)

  - blacklist.conf: blacklist 7b73305160f1, unneeded cleanup

  - blacklist.conf: da0510c47519fe0999cffe316e1d370e29f952be
    # FRV not applicable to SLE

  - blkfront: add uevent for size change (bnc#1036632).

  - block: Fix front merge check (bsc#1051239).

  - brcmfmac: Fix glom_skb leak in brcmf_sdiod_recv_chain
    (bsc#1031717).

  - btrfs: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - btrfs: add cond_resched to btrfs_qgroup_trace_leaf_items
    (bsc#1028286).

  - btrfs: fix lockup in find_free_extent with read-only
    block groups (bsc#1046682).

  - cpuidle: dt: Add missing 'of_node_put()' (bnc#1022476).

  - cxgb4: fix BUG() on interrupt deallocating path of ULD
    (bsc#1005778).

  - cxgb4: fix a NULL dereference (bsc#1005778).

  - cxgb4: fix memory leak in init_one() (bsc#1005778).

  - dentry name snapshots (bsc#1049483).

  - device-dax: fix sysfs attribute deadlock (bsc#1048919).

  - drm/i915: Fix scaler init during CRTC HW state readout
    (bsc#1031717).

  - drm/vmwgfx: Fix large topology crash (bsc#1048155).

  - drm/vmwgfx: Support topology greater than texture size
    (bsc#1048155).

  - efi/libstub: Skip GOP with PIXEL_BLT_ONLY format
    (bnc#974215).

  - ext2: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - ext4: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - ext4: avoid unnecessary stalls in ext4_evict_inode()
    (bsc#1049486).

  - ext4: handle the rest of ext4_mb_load_buddy() ENOMEM
    errors (bsc#1012829).

  - gcov: add support for gcc version >= 6 (bsc#1051663).

  - gcov: support GCC 7.1 (bsc#1051663).

  - gfs2: fix flock panic issue (bsc#1012829).

  - hv: print extra debug in kvp_on_msg in error paths
    (bnc#1039153).

  - hv_netvsc: Exclude non-TCP port numbers from vRSS
    hashing (bsc#1048421).

  - hv_netvsc: Fix the queue index computation in forwarding
    case (bsc#1048421).

  - i2c: designware-baytrail: fix potential NULL pointer
    dereference on dev (bsc#1011913).

  - introduce the walk_process_tree() helper (bnc#1022476).

  - iommu/amd: Fix interrupt remapping when disable
    guest_mode (bsc#1051471).

  - iwlwifi: mvm: reset the fw_dump_desc pointer after
    ASSERT (bsc#1031717).

  - iwlwifi: mvm: unconditionally stop device after init
    (bsc#1031717).

  - iwlwifi: pcie: fix command completion name debug
    (bsc#1031717).

  - kABI-fix for 'x86/panic: replace smp_send_stop() with
    kdump friendly version in panic path' (bsc#1051478).

  - kABI: protect lwtunnel include in ip6_route.h (kabi).

  - kABI: protect struct iscsi_tpg_attrib (kabi).

  - kABI: protect struct tpm_chip (kabi).

  - kABI: protect struct xfrm_dst (kabi).

  - kvm: nVMX: Fix nested_vmx_check_msr_bitmap_controls
    (bsc#1051478).

  - libnvdimm, pmem: fix a NULL pointer BUG in
    nd_pmem_notify (bsc#1048919).

  - libnvdimm, region: fix flush hint detection crash
    (bsc#1048919).

  - libnvdimm: fix badblock range handling of ARS range
    (bsc#1051048).

  - lightnvm: fix 'warning: &lsquo;ret&rsquo; may be used
    uninitialized' (FATE#319466).

  - md-cluster: Fix a memleak in an error handling path
    (bsc#1049289).

  - mm: make PR_SET_THP_DISABLE immediately active
    (bnc#1048891).

  - mwifiex: do not update MCS set from hostapd
    (bsc#1031717).

  - net/ena: switch to pci_alloc_irq_vectors (bsc#1047121).

  - net: ena: add hardware hints capability to the driver
    (bsc#1047121).

  - net: ena: add hardware hints capability to the driver
    (bsc#1047121).

  - net: ena: add missing return when
    ena_com_get_io_handlers() fails (bsc#1047121).

  - net: ena: add missing return when
    ena_com_get_io_handlers() fails (bsc#1047121).

  - net: ena: add missing unmap bars on device removal
    (bsc#1047121).

  - net: ena: add missing unmap bars on device removal
    (bsc#1047121).

  - net: ena: add reset reason for each device FLR
    (bsc#1047121).

  - net: ena: add reset reason for each device FLR
    (bsc#1047121).

  - net: ena: add support for out of order rx buffers refill
    (bsc#1047121).

  - net: ena: add support for out of order rx buffers refill
    (bsc#1047121).

  - net: ena: allow the driver to work with small number of
    msix vectors (bsc#1047121).

  - net: ena: allow the driver to work with small number of
    msix vectors (bsc#1047121).

  - net: ena: bug fix in lost tx packets detection mechanism
    (bsc#1047121).

  - net: ena: bug fix in lost tx packets detection mechanism
    (bsc#1047121).

  - net: ena: change return value for unsupported features
    unsupported return value (bsc#1047121).

  - net: ena: change return value for unsupported features
    unsupported return value (bsc#1047121).

  - net: ena: change sizeof() argument to be the type
    pointer (bsc#1047121).

  - net: ena: change sizeof() argument to be the type
    pointer (bsc#1047121).

  - net: ena: disable admin msix while working in polling
    mode (bsc#1047121).

  - net: ena: disable admin msix while working in polling
    mode (bsc#1047121).

  - net: ena: fix bug that might cause hang after
    consecutive open/close interface (bsc#1047121).

  - net: ena: fix bug that might cause hang after
    consecutive open/close interface (bsc#1047121).

  - net: ena: fix race condition between submit and
    completion admin command (bsc#1047121).

  - net: ena: fix race condition between submit and
    completion admin command (bsc#1047121).

  - net: ena: fix rare uncompleted admin command false alarm
    (bsc#1047121).

  - net: ena: fix rare uncompleted admin command false alarm
    (bsc#1047121).

  - net: ena: fix theoretical Rx hang on low memory systems
    (bsc#1047121).

  - net: ena: fix theoretical Rx hang on low memory systems
    (bsc#1047121).

  - net: ena: separate skb allocation to dedicated function
    (bsc#1047121).

  - net: ena: separate skb allocation to dedicated function
    (bsc#1047121).

  - net: ena: update driver's rx drop statistics
    (bsc#1047121).

  - net: ena: update driver's rx drop statistics
    (bsc#1047121).

  - net: ena: update ena driver to version 1.1.7
    (bsc#1047121).

  - net: ena: update ena driver to version 1.1.7
    (bsc#1047121).

  - net: ena: update ena driver to version 1.2.0
    (bsc#1047121).

  - net: ena: update ena driver to version 1.2.0
    (bsc#1047121).

  - net: ena: use lower_32_bits()/upper_32_bits() to split
    dma address (bsc#1047121).

  - net: ena: use lower_32_bits()/upper_32_bits() to split
    dma address (bsc#1047121).

  - net: ena: use napi_schedule_irqoff when possible
    (bsc#1047121).

  - net: ena: use napi_schedule_irqoff when possible
    (bsc#1047121).

  - net: hns: Bugfix for Tx timeout handling in hns driver
    (bsc#1048451).

  - net: phy: Do not perform software reset for Generic PHY
    (bsc#1042286).

  - nvme: also provide a UUID in the WWID sysfs attribute
    (bsc#1048146).

  - nvme: wwid_show: strip trailing 0-bytes (bsc#1048146).

  - nvmet: identify controller: improve standard compliance
    (bsc#1048146).

  - ocfs2: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - ocfs2: Make ocfs2_set_acl() static (bsc#1030552).

  - ocfs2: fix deadlock caused by recursive locking in xattr
    (bsc#1012829).

  - perf/x86/intel: Cure bogus unwind from PEBS entries
    (bsc#1051478).

  - perf/x86/intel: Fix PEBSv3 record drain (bsc#1051478).

  - perf/x86: Fix spurious NMI with PEBS Load Latency event
    (bsc#1051478).

  - platform/x86: ideapad-laptop: Add IdeaPad 310-15IKB to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add IdeaPad V310-15ISK to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add IdeaPad V510-15IKB to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Lenovo Yoga 910-13IKB
    to no_hw_rfkill dmi list (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Y520-15IKBN to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Y700 15-ACZ to
    no_hw_rfkill DMI list (bsc#1051022).

  - platform/x86: ideapad-laptop: Add Y720-15IKBN to
    no_hw_rfkill (bsc#1051022).

  - platform/x86: ideapad-laptop: Add several models to
    no_hw_rfkill (bsc#1051022).

  - powerpc/fadump: Add a warning when 'fadump_reserve_mem='
    is used (bsc#1049231).

  - powerpc: Add POWER9 architected mode to cputable
    (bsc#1048916, fate#321439).

  - powerpc: Support POWER9 in architected mode
    (bsc#1048916, fate#321439).

  - prctl: propagate has_child_subreaper flag to every
    descendant (bnc#1022476).

  - qed: Add missing static/local dcbx info (bsc#1019695).

  - qed: Correct print in iscsi error-flow (bsc#1019695).

  - reiserfs: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - reorder upstream commit d0c2c9973ecd net: use core MTU
    range checking in virt drivers

  - rpm/kernel-binary.spec.in: find-debuginfo.sh should not
    touch build-id This needs rpm-4.14+ (bsc#964063).

  - s390/crash: Remove unused KEXEC_NOTE_BYTES
    (bsc#1049706).

  - s390/kdump: remove code to create ELF notes in the
    crashed system (bsc#1049706).

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

  - scsi: aacraid: Do not copy uninitialized stack memory to
    userspace (bsc#1048912).

  - scsi: aacraid: fix leak of data from stack back to
    userspace (bsc#1048912).

  - scsi: kABI fix for new state STARGET_CREATED_REMOVE
    (bsc#1013887).

  - scsi: lpfc: Add MDS Diagnostic support (bsc#1037838).

  - scsi: lpfc: Add auto EQ delay logic (bsc#1042257).

  - scsi: lpfc: Added recovery logic for running out of
    NVMET IO context resources (bsc#1037838).

  - scsi: lpfc: Adding additional stats counters for nvme
    (bsc#1037838).

  - scsi: lpfc: Cleanup entry_repost settings on SLI4 queues
    (bsc#1037838).

  - scsi: lpfc: Driver responds LS_RJT to Beacon Off ELS -
    Linux (bsc#1044623).

  - scsi: lpfc: Fix NMI watchdog assertions when running
    nvmet IOPS tests (bsc#1037838).

  - scsi: lpfc: Fix NVME I+T not registering NVME as a
    supported FC4 type (bsc#1037838).

  - scsi: lpfc: Fix NVMEI driver not decrementing counter
    causing bad rport state (bsc#1037838).

  - scsi: lpfc: Fix NVMEI's handling of NVMET's PRLI
    response attributes (bsc#1037838).

  - scsi: lpfc: Fix SLI3 drivers attempting NVME ELS
    commands (bsc#1044623).

  - scsi: lpfc: Fix crash after firmware flash when IO is
    running (bsc#1044623).

  - scsi: lpfc: Fix crash doing IO with resets
    (bsc#1044623).

  - scsi: lpfc: Fix crash in lpfc_sli_ringtxcmpl_put when
    nvmet gets an abort request (bsc#1044623).

  - scsi: lpfc: Fix debugfs root inode 'lpfc' not getting
    deleted on driver unload (bsc#1037838).

  - scsi: lpfc: Fix defects reported by Coverity Scan
    (bsc#1042257).

  - scsi: lpfc: Fix nvme io stoppage after link bounce
    (bsc#1045404).

  - scsi: lpfc: Fix nvmet RQ resource needs for large block
    writes (bsc#1037838).

  - scsi: lpfc: Fix system crash when port is reset
    (bsc#1037838).

  - scsi: lpfc: Fix system panic when express lane enabled
    (bsc#1044623).

  - scsi: lpfc: Fix used-RPI accounting problem
    (bsc#1037838).

  - scsi: lpfc: Reduce time spent in IRQ for received NVME
    commands (bsc#1044623).

  - scsi: lpfc: Separate NVMET RQ buffer posting from IO
    resources SGL/iocbq/context (bsc#1037838).

  - scsi: lpfc: Separate NVMET data buffer pool fir ELS/CT
    (bsc#1037838).

  - scsi: lpfc: Vport creation is failing with 'Link Down'
    error (bsc#1044623).

  - scsi: lpfc: fix refcount error on node list
    (bsc#1045404).

  - scsi: lpfc: update to revision to 11.4.0.1
    (bsc#1044623).

  - scsi: lpfc: update version to 11.2.0.14 (bsc#1037838).

  - scsi: qedf: Fix a return value in case of error in
    'qedf_alloc_global_queues' (bsc#1048912).

  - scsi: qedi: Remove WARN_ON for untracked cleanup
    (bsc#1044443).

  - scsi: qedi: Remove WARN_ON from clear task context
    (bsc#1044443).

  - sfc: Add ethtool -m support for QSFP modules
    (bsc#1049619).

  - string.h: add memcpy_and_pad() (bsc#1048146).

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

  - x86/platform/uv/BAU: Disable BAU on single hub
    configurations (bsc#1050320).

  - x86/platform/uv/BAU: Fix congested_response_us not
    taking effect (bsc#1050322).

  - xen/pvh*: Support > 32 VCPUs at domain restore
    (bnc#1045563).

  - xen: hold lock_device_hotplug throughout vcpu hotplug
    operations (bsc#1042422).

  - xfs: Do not clear SGID when inheriting ACLs
    (bsc#1030552).

  - xfs: detect and handle invalid iclog size set by mkfs
    (bsc#1043598).

  - xfs: detect and trim torn writes during log recovery
    (bsc#1036215).

  - xfs: do not BUG() on mixed direct and mapped I/O
    (bsc#1050188).

  - xfs: refactor and open code log record crc check
    (bsc#1036215).

  - xfs: refactor log record start detection into a new
    helper (bsc#1036215).

  - xfs: return start block of first bad log record during
    recovery (bsc#1036215).

  - xfs: support a crc verification only log record pass
    (bsc#1036215).

  - xgene: Do not fail probe, if there is no clk resource
    for SGMII interfaces (bsc#1048501)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005778"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030552"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045404"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049361"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049706"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051048"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051471"
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
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.79-4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.79-4.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-devel / kernel-macros / kernel-source / etc");
}
