#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1160.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104075);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000252", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14489");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1160)");
  script_summary(english:"Check for the openSUSE-2017-1160 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.90 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000252: The KVM subsystem in the Linux kernel
    allowed guest OS users to cause a denial of service
    (assertion failure, and hypervisor hang or crash) via an
    out-of bounds guest_irq value, related to
    arch/x86/kvm/vmx.c and virt/kvm/eventfd.c (bnc#1058038).

  - CVE-2017-14489: The iscsi_if_rx function in
    drivers/scsi/scsi_transport_iscsi.c in the Linux kernel
    allowed local users to cause a denial of service (panic)
    by leveraging incorrect length validation (bnc#1059051).

  - CVE-2017-12153: A security flaw was discovered in the
    nl80211_set_rekey_data() function in
    net/wireless/nl80211.c in the Linux kernel This function
    did not check whether the required attributes are
    present in a Netlink request. This request can be issued
    by a user with the CAP_NET_ADMIN capability and may
    result in a NULL pointer dereference and system crash
    (bnc#1058410).

  - CVE-2017-12154: The prepare_vmcs02 function in
    arch/x86/kvm/vmx.c in the Linux kernel did not ensure
    that the 'CR8-load exiting' and 'CR8-store exiting' L0
    vmcs02 controls exist in cases where L1 omits the 'use
    TPR shadow' vmcs12 control, which allowed KVM L2 guest
    OS users to obtain read and write access to the hardware
    CR8 register (bnc#1058507).

The following non-security bugs were fixed :

  - arc: Re-enable MMU upon Machine Check exception
    (bnc#1012382).

  - arm64: fault: Route pte translation faults via
    do_translation_fault (bnc#1012382).

  - arm64: Make sure SPsel is always set (bnc#1012382).

  - arm: pxa: add the number of DMA requestor lines
    (bnc#1012382).

  - arm: pxa: fix the number of DMA requestor lines
    (bnc#1012382).

  - bcache: correct cache_dirty_target in
    __update_writeback_rate() (bnc#1012382).

  - bcache: Correct return value for sysfs attach errors
    (bnc#1012382).

  - bcache: do not subtract sectors_to_gc for bypassed IO
    (bnc#1012382).

  - bcache: fix bch_hprint crash and improve output
    (bnc#1012382).

  - bcache: fix for gc and write-back race (bnc#1012382).

  - bcache: Fix leak of bdev reference (bnc#1012382).

  - bcache: initialize dirty stripes in flash_dev_run()
    (bnc#1012382).

  - block: Relax a check in blk_start_queue() (bnc#1012382).

  - bsg-lib: do not free job in bsg_prepare_job
    (bnc#1012382).

  - btrfs: change how we decide to commit transactions
    during flushing (bsc#1060197).

  - btrfs: fix NULL pointer dereference from
    free_reloc_roots() (bnc#1012382).

  - btrfs: prevent to set invalid default subvolid
    (bnc#1012382).

  - btrfs: propagate error to btrfs_cmp_data_prepare caller
    (bnc#1012382).

  - btrfs: qgroup: move noisy underflow warning to debugging
    build (bsc#1055755).

  - cifs: Fix SMB3.1.1 guest authentication to Samba
    (bnc#1012382).

  - cifs: release auth_key.response for reconnect
    (bnc#1012382).

  - crypto: AF_ALG - remove SGL terminator indicator when
    chaining (bnc#1012382).

  - crypto: talitos - Do not provide setkey for non hmac
    hashing algs (bnc#1012382).

  - crypto: talitos - fix sha224 (bnc#1012382).

  - cxl: Fix driver use count (bnc#1012382).

  - dmaengine: mmp-pdma: add number of requestors
    (bnc#1012382).

  - drivers: net: phy: xgene: Fix mdio write (bsc#1057383).

  - drm: Add driver-private objects to atomic state
    (bsc#1055493).

  - drm/dp: Introduce MST topology state to track available
    link bandwidth (bsc#1055493).

  - efi/fb: Avoid reconfiguration of BAR that covers the
    framebuffer (bsc#1051987).

  - efi/fb: Correct PCI_STD_RESOURCE_END usage
    (bsc#1051987).

  - ext4: fix incorrect quotaoff if the quota feature is
    enabled (bnc#1012382).

  - ext4: fix quota inconsistency during orphan cleanup for
    read-only mounts (bnc#1012382).

  - f2fs: check hot_data for roll-forward recovery
    (bnc#1012382).

  - fix xen_swiotlb_dma_mmap prototype (bnc#1012382).

  - ftrace: Fix memleak when unregistering dynamic ops when
    tracing disabled (bnc#1012382).

  - ftrace: Fix selftest goto location on error
    (bnc#1012382).

  - genirq: Fix for_each_action_of_desc() macro
    (bsc#1061064).

  - getcwd: Close race with d_move called by lustre
    (bsc#1052593).

  - gfs2: Fix debugfs glocks dump (bnc#1012382).

  - gianfar: Fix Tx flow control deactivation (bnc#1012382).

  - hid: usbhid: Add HID_QUIRK_NOGET for Aten CS-1758 KVM
    switch (bnc#1022967).

  - input: i8042 - add Gigabyte P57 to the keyboard reset
    table (bnc#1012382).

  - iommu/vt-d: Avoid calling virt_to_phys() on NULL pointer
    (bsc#1061067).

  - ipv6: accept 64k - 1 packet length in
    ip6_find_1stfragopt() (bnc#1012382).

  - ipv6: add rcu grace period before freeing fib6_node
    (bnc#1012382).

  - ipv6: fix memory leak with multiple tables during netns
    destruction (bnc#1012382).

  - ipv6: fix sparse warning on rt6i_node (bnc#1012382).

  - ipv6: fix typo in fib6_net_exit() (bnc#1012382).

  - iw_cxgb4: put ep reference in pass_accept_req()
    (fate#321658 bsc#1005778 fate#321660 bsc#1005780
    fate#321661 bsc#1005781).

  - KABI fix drivers/nvme/target/nvmet.h (bsc#1058550).

  - kabi/severities: ignore nfs_pgio_data_destroy

  - kABI: Workaround kABI breakage of AMD-AVIC fixes
    (bsc#1044503).

  - keys: fix writing past end of user-supplied buffer in
    keyring_read() (bnc#1012382).

  - keys: prevent creating a different user's keyrings
    (bnc#1012382).

  - keys: prevent KEYCTL_READ on negative key (bnc#1012382).

  - kvm: Add struct kvm_vcpu pointer parameter to
    get_enable_apicv() (bsc#1044503).

  - kvm: async_pf: Fix #DF due to inject 'Page not Present'
    and 'Page Ready' exceptions simultaneously
    (bsc#1061017).

  - kvm: PPC: Book3S: Fix race and leak in
    kvm_vm_ioctl_create_spapr_tce() (bnc#1012382).

  - kvm: SVM: Add a missing 'break' statement (bsc#1061017).

  - kvm: SVM: Add irqchip_split() checks before enabling
    AVIC (bsc#1044503).

  - kvm: SVM: delete avic_vm_id_bitmap (2 megabyte static
    array) (bsc#1059500).

  - kvm: SVM: Refactor AVIC vcpu initialization into
    avic_init_vcpu() (bsc#1044503).

  - kvm: VMX: do not change SN bit in vmx_update_pi_irte()
    (bsc#1061017).

  - kvm: VMX: remove WARN_ON_ONCE in
    kvm_vcpu_trigger_posted_interrupt (bsc#1061017).

  - kvm: VMX: use cmpxchg64 (bnc#1012382).

  - mac80211: flush hw_roc_start work before cancelling the
    ROC (bnc#1012382).

  - md/bitmap: disable bitmap_resize for file-backed bitmaps
    (bsc#1061172).

  - md/raid5: preserve STRIPE_ON_UNPLUG_LIST in
    break_stripe_batch_list (bnc#1012382).

  - md/raid5: release/flush io in raid5_do_work()
    (bnc#1012382).

  - media: uvcvideo: Prevent heap overflow when accessing
    mapped controls (bnc#1012382).

  - media: v4l2-compat-ioctl32: Fix timespec conversion
    (bnc#1012382).

  - mips: math-emu: <MAXA|MINA>.<D|S>: Fix cases of both
    infinite inputs (bnc#1012382).

  - mips: math-emu: <MAXA|MINA>.<D|S>: Fix cases of input
    values with opposite signs (bnc#1012382).

  - mips: math-emu: <MAX|MAXA|MIN|MINA>.<D|S>: Fix cases of
    both inputs zero (bnc#1012382).

  - mips: math-emu: <MAX|MAXA|MIN|MINA>.<D|S>: Fix quiet NaN
    propagation (bnc#1012382).

  - mips: math-emu: <MAX|MIN>.<D|S>: Fix cases of both
    inputs negative (bnc#1012382).

  - mips: math-emu: MINA.<D|S>: Fix some cases of infinity
    and zero inputs (bnc#1012382).

  - mm: prevent double decrease of nr_reserved_highatomic
    (bnc#1012382).

  - nfsd: Fix general protection fault in
    release_lock_stateid() (bnc#1012382).

  - nvme-fabrics: generate spec-compliant UUID NQNs
    (bsc#1057498).

  - nvmet: Move serial number from controller to subsystem
    (bsc#1058550).

  - nvmet: preserve controller serial number between reboots
    (bsc#1058550).

  - pci: Allow PCI express root ports to find themselves
    (bsc#1061046).

  - pci: fix oops when try to find Root Port for a PCI
    device (bsc#1061046).

  - pci: Fix race condition with driver_override
    (bnc#1012382).

  - pci: Mark AMD Stoney GPU ATS as broken (bsc#1061046).

  - pci: shpchp: Enable bridge bus mastering if MSI is
    enabled (bnc#1012382).

  - perf/x86: Fix RDPMC vs. mm_struct tracking
    (bsc#1061831).

  - perf/x86: kABI Workaround for 'perf/x86: Fix RDPMC vs.
    mm_struct tracking' (bsc#1061831).

  - perf: xgene: Add APM X-Gene SoC Performance Monitoring
    Unit driver (bsc#1036737).

  - perf: xgene: Include module.h (bsc#1036737).

  - perf: xgene: Move PMU leaf functions into function
    pointer structure (bsc#1036737).

  - perf: xgene: Parse PMU subnode from the match table
    (bsc#1036737).

  - powerpc: Fix DAR reporting when alignment handler faults
    (bnc#1012382).

  - powerpc/perf: Cleanup of PM_BR_CMPL vs. PM_BRU_CMPL in
    Power9 event list (bsc#1056686, fate#321438,
    bsc#1047238, git-fixes 34922527a2bc).

  - powerpc/perf: Factor out PPMU_ONLY_COUNT_RUN check code
    from power8 (fate#321438, bsc#1053043, git-fixes
    efe881afdd999).

  - powerpc/pseries: Fix parent_dn reference leak in
    add_dt_node() (bnc#1012382).

  - qlge: avoid memcpy buffer overflow (bnc#1012382).

  - rdma/bnxt_re: Allocate multiple notification queues
    (bsc#1037579).

  - rdma/bnxt_re: Implement the alloc/get_hw_stats callback
    (bsc#1037579).

  - Revert 'net: fix percpu memory leaks' (bnc#1012382).

  - Revert 'net: phy: Correctly process PHY_HALTED in
    phy_stop_machine()' (bnc#1012382).

  - Revert 'net: use lib/percpu_counter API for
    fragmentation mem accounting' (bnc#1012382).

  - Revert 'Update
    patches.fixes/xfs-refactor-log-record-unpack-and-data-pr
    ocessing.patch (bsc#1043598, bsc#1036215).' 

  - Revert 'xfs: detect and handle invalid iclog size set by
    mkfs (bsc#1043598).'

  - Revert 'xfs: detect and trim torn writes during log
    recovery (bsc#1036215).' 

  - Revert 'xfs: refactor and open code log record crc check
    (bsc#1036215).'

  - Revert 'xfs: refactor log record start detection into a
    new helper (bsc#1036215).'

  - Revert 'xfs: return start block of first bad log record
    during recovery (bsc#1036215).'

  - Revert 'xfs: support a crc verification only log record
    pass (bsc#1036215).'

  - scsi: ILLEGAL REQUEST + ASC==27 => target failure
    (bsc#1059465).

  - scsi: megaraid_sas: Check valid aen class range to avoid
    kernel panic (bnc#1012382).

  - scsi: megaraid_sas: Return pended IOCTLs with cmd_status
    MFI_STAT_WRONG_STATE in case adapter is dead
    (bnc#1012382).

  - scsi: sg: factor out sg_fill_request_table()
    (bnc#1012382).

  - scsi: sg: fixup infoleak when using SG_GET_REQUEST_TABLE
    (bnc#1012382).

  - scsi: sg: off by one in sg_ioctl() (bnc#1012382).

  - scsi: sg: remove 'save_scat_len' (bnc#1012382).

  - scsi: sg: use standard lists for sg_requests
    (bnc#1012382).

  - scsi: storvsc: fix memory leak on ring buffer busy
    (bnc#1012382).

  - scsi_transport_fc: Also check for NOTPRESENT in
    fc_remote_port_add() (bsc#1037890).

  - scsi: zfcp: add handling for FCP_RESID_OVER to the fcp
    ingress path (bnc#1012382).

  - scsi: zfcp: fix capping of unsuccessful GPN_FT SAN
    response trace records (bnc#1012382).

  - scsi: zfcp: fix missing trace records for early returns
    in TMF eh handlers (bnc#1012382).

  - scsi: zfcp: fix passing fsf_req to SCSI trace on TMF to
    correlate with HBA (bnc#1012382).

  - scsi: zfcp: fix payload with full FCP_RSP IU in SCSI
    trace records (bnc#1012382).

  - scsi: zfcp: fix queuecommand for scsi_eh commands when
    DIX enabled (bnc#1012382).

  - scsi: zfcp: trace HBA FSF response by default on dismiss
    or timedout late response (bnc#1012382).

  - scsi: zfcp: trace high part of 'new' 64 bit SCSI LUN
    (bnc#1012382).

  - seccomp: fix the usage of get/put_seccomp_filter() in
    seccomp_get_filter() (bnc#1012382).

  - skd: Avoid that module unloading triggers a
    use-after-free (bnc#1012382).

  - skd: Submit requests to firmware before triggering the
    doorbell (bnc#1012382).

  - smb3: Do not ignore O_SYNC/O_DSYNC and O_DIRECT flags
    (bnc#1012382).

  - smb: Validate negotiate (to protect against downgrade)
    even if signing off (bnc#1012382).

  - swiotlb-xen: implement xen_swiotlb_dma_mmap callback
    (bnc#1012382).

  - timer/sysclt: Restrict timer migration sysctl values to
    0 and 1 (bnc#1012382).

  - tracing: Apply trace_clock changes to instance max
    buffer (bnc#1012382).

  - tracing: Erase irqsoff trace with empty write
    (bnc#1012382).

  - tracing: Fix trace_pipe behavior for instance traces
    (bnc#1012382).

  - tty: fix __tty_insert_flip_char regression
    (bnc#1012382).

  - tty: improve tty_insert_flip_char() fast path
    (bnc#1012382).

  - tty: improve tty_insert_flip_char() slow path
    (bnc#1012382).

  - Update
    patches.drivers/0029-perf-xgene-Remove-bogus-IS_ERR-chec
    k.patch (bsc#1036737).

  - vfs: Return -ENXIO for negative SEEK_HOLE / SEEK_DATA
    offsets (bnc#1012382).

  - video: fbdev: aty: do not leak uninitialized padding in
    clk to userspace (bnc#1012382).

  - Workaround for kABI compatibility with DP-MST patches
    (bsc#1055493).

  - x86/cpu/amd: Hide unused legacy_fixup_core_id() function
    (bsc#1060229).

  - x86/cpu/amd: Limit cpu_core_id fixup to families older
    than F17h (bsc#1060229).

  - x86/fpu: Do not let userspace set bogus xcomp_bv
    (bnc#1012382).

  - x86/fsgsbase/64: Report FSBASE and GSBASE correctly in
    core dumps (bnc#1012382).

  - x86/ldt: Fix off by one in get_segment_base()
    (bsc#1061872).

  - x86/mm: Fix boot crash caused by incorrect loop count
    calculation in sync_global_pgds() (bsc#1058512).

  - x86/mm: Fix fault error path using unsafe vma pointer
    (fate#321300)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061872"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.90-28.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.90-28.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.90-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.90-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-devel / kernel-macros / kernel-source / etc");
}
