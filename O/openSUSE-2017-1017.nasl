#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1017.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103155);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12134", "CVE-2017-14051");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1017)");
  script_summary(english:"Check for the openSUSE-2017-1017 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.85 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-14051: An integer overflow in the
    qla2x00_sysfs_write_optrom_ctl function in
    drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash) by leveraging root access
    (bnc#1056588).

  - CVE-2017-12134: The xen_biovec_phys_mergeable function
    in drivers/xen/biomerge.c in Xen might allow local OS
    guest users to corrupt block device data streams and
    consequently obtain sensitive memory information, cause
    a denial of service, or gain host OS privileges by
    leveraging incorrect block IO merge-ability calculation
    (bnc#1051790 bnc#1053919).

The following non-security bugs were fixed :

  - acpi: apd: Add clock frequency for Hisilicon Hip07/08
    I2C controller (bsc#1049291).

  - acpi: apd: Fix HID for Hisilicon Hip07/08 (bsc#1049291).

  - acpi: APEI: Enable APEI multiple GHES source to share a
    single external IRQ (bsc#1053627).

  - acpi: irq: Fix return code of acpi_gsi_to_irq()
    (bsc#1053627).

  - acpi: pci: fix GIC irq model default PCI IRQ polarity
    (bsc#1053629).

  - acpi: scan: Prefer devices without _HID for _ADR
    matching (git-fixes).

  - Add 'shutdown' to 'struct class' (bsc#1053117).

  - alsa: hda - Add stereo mic quirk for Lenovo G50-70
    (17aa:3978) (bsc#1020657).

  - alsa: hda - Implement mic-mute LED mode enum
    (bsc#1055013).

  - alsa: hda - Workaround for i915 KBL breakage
    (bsc#1048356,bsc#1047989,bsc#1055272).

  - alsa: ice1712: Add support for STAudio ADCIII
    (bsc#1048934).

  - alsa: usb-audio: Apply sample rate quirk to Sennheiser
    headset (bsc#1052580).

  - arm64: do not trace atomic operations (bsc#1055290).

  - block: add kblock_mod_delayed_work_on() (bsc#1050211).

  - block: Make blk_mq_delay_kick_requeue_list() rerun the
    queue at a quiet time (bsc#1050211).

  - block: provide bio_uninit() free freeing integrity/task
    associations (bsc#1050211).

  - block: return on congested block device (FATE#321994).

  - bluetooth: bnep: fix possible might sleep error in
    bnep_session (bsc#1031784).

  - bluetooth: cmtp: fix possible might sleep error in
    cmtp_session (bsc#1031784).

  - bnxt_en: Add a callback to inform RDMA driver during PCI
    shutdown (bsc#1053309).

  - bnxt_en: Add additional chip ID definitions
    (bsc#1053309).

  - bnxt_en: Add bnxt_get_num_stats() to centrally get the
    number of ethtool stats (bsc#1053309).

  - bnxt_en: Add missing logic to handle TPA end error
    conditions (bsc#1053309).

  - bnxt_en: Add PCI IDs for BCM57454 VF devices
    (bsc#1053309).

  - bnxt_en: Allow the user to set ethtool stats-block-usecs
    to 0 (bsc#1053309).

  - bnxt_en: Call bnxt_dcb_init() after getting firmware
    DCBX configuration (bsc#1053309).

  - bnxt_en: Check status of firmware DCBX agent before
    setting DCB_CAP_DCBX_HOST (bsc#1053309).

  - bnxt_en: Fix bug in ethtool -L (bsc#1053309).

  - bnxt_en: Fix netpoll handling (bsc#1053309).

  - bnxt_en: Fix race conditions in .ndo_get_stats64()
    (bsc#1053309).

  - bnxt_en: Fix SRIOV on big-endian architecture
    (bsc#1053309).

  - bnxt_en: Fix xmit_more with BQL (bsc#1053309).

  - bnxt_en: Implement ndo_bridge_(get|set)link methods
    (bsc#1053309).

  - bnxt_en: Implement xmit_more (bsc#1053309).

  - bnxt_en: Optimize doorbell write operations for newer
    chips (bsc#1053309).

  - bnxt_en: Pass in sh parameter to bnxt_set_dflt_rings()
    (bsc#1053309).

  - bnxt_en: Report firmware DCBX agent (bsc#1053309).

  - bnxt_en: Retrieve the hardware bridge mode from the
    firmware (bsc#1053309).

  - bnxt_en: Set ETS min_bw parameter for older firmware
    (bsc#1053309).

  - bnxt_en: Support for Short Firmware Message
    (bsc#1053309).

  - bnxt_en: Update firmware interface spec to 1.8.0
    (bsc#1053309).

  - bnxt: fix unsigned comparsion with 0 (bsc#1053309).

  - bnxt: fix unused variable warnings (bsc#1053309).

  - btrfs: fix early ENOSPC due to delalloc (bsc#1049226).

  - btrfs: nowait aio: Correct assignment of pos
    (FATE#321994).

  - btrfs: nowait aio support (FATE#321994).

  - ceph: avoid accessing freeing inode in
    ceph_check_delayed_caps() (bsc#1048228).

  - ceph: avoid invalid memory dereference in the middle of
    umount (bsc#1048228).

  - ceph: cleanup writepage_nounlock() (bsc#1048228).

  - ceph: do not re-send interrupted flock request
    (bsc#1048228).

  - ceph: getattr before read on ceph.* xattrs
    (bsc#1048228).

  - ceph: handle epoch barriers in cap messages
    (bsc#1048228).

  - ceph: new mount option that specifies fscache uniquifier
    (bsc#1048228).

  - ceph: redirty page when writepage_nounlock() skips
    unwritable page (bsc#1048228).

  - ceph: remove special ack vs commit behavior
    (bsc#1048228).

  - ceph: remove useless page->mapping check in
    writepage_nounlock() (bsc#1048228).

  - ceph: re-request max size after importing caps
    (bsc#1048228).

  - ceph: update ceph_dentry_info::lease_session when
    necessary (bsc#1048228).

  - ceph: update the 'approaching max_size' code
    (bsc#1048228).

  - ceph: when seeing write errors on an inode, switch to
    sync writes (bsc#1048228).

  - cifs: Fix maximum SMB2 header size (bsc#1056185).

  - clocksource/drivers/arm_arch_timer: Fix mem frame loop
    initialization (bsc#1055709).

  - crush: assume weight_set != null imples weight_set_size
    > 0 (bsc#1048228).

  - crush: crush_init_workspace starts with struct
    crush_work (bsc#1048228).

  - crush: implement weight and id overrides for straw2
    (bsc#1048228).

  - crush: remove an obsolete comment (bsc#1048228).

  - crypto: chcr - Add ctr mode and process large sg entries
    for cipher (bsc#1048325).

  - crypto: chcr - Avoid changing request structure
    (bsc#1048325).

  - crypto: chcr - Ensure Destination sg entry size less
    than 2k (bsc#1048325).

  - crypto: chcr - Fix fallback key setting (bsc#1048325).

  - crypto: chcr - Pass lcb bit setting to firmware
    (bsc#1048325).

  - crypto: chcr - Return correct error code (bsc#1048325).

  - cxgb4: update latest firmware version supported
    (bsc#1048327).

  - cxgbit: add missing __kfree_skb() (bsc#1052095).

  - cxgbit: fix sg_nents calculation (bsc#1052095).

  - Disable patch
    0017-nvmet_fc-Simplify-sg-list-handling.patch
    (bsc#1052384)

  - dm: make flush bios explicitly sync (bsc#1050211).

  - dm mpath: do not lock up a CPU with requeuing activity
    (bsc#1048912).

  - drivers: net: xgene: Fix wrong logical operation
    (bsc#1056827).

  - drm/vmwgfx: Limit max desktop dimensions to 8Kx8K
    (bsc#1048155).

  - ext4: nowait aio support (FATE#321994).

  - fs: Introduce filemap_range_has_page() (FATE#321994).

  - fs: Introduce RWF_NOWAIT and FMODE_AIO_NOWAIT
    (FATE#321994).

  - fs: pass on flags in compat_writev (bsc#1050211).

  - fs: return if direct I/O will trigger writeback
    (FATE#321994).

  - fs: Separate out kiocb flags setup based on RWF_* flags
    (FATE#321994).

  - fs: Use RWF_* flags for AIO operations (FATE#321994).

  - fuse: initialize the flock flag in fuse_file on
    allocation (git-fixes).

  - i2c: designware: Add ACPI HID for Hisilicon Hip07/08 I2C
    controller (bsc#1049291).

  - i2c: designware: Convert to use unified device property
    API (bsc#1049291).

  - i2c: xgene: Set ACPI_COMPANION_I2C (bsc#1053633).

  - i2c: xgene-slimpro: Add ACPI support by using PCC
    mailbox (bsc#1053633).

  - i2c: xgene-slimpro: include linux/io.h for memremap
    (bsc#1053633).

  - i2c: xgene-slimpro: Use a single function to send
    command message (bsc#1053633).

  - i40e/i40evf: fix out-of-bounds read of cpumask
    (bsc#1053685).

  - ib/iser: Fix connection teardown race condition
    (bsc#1050211).

  - iscsi-target: fix invalid flags in text response
    (bsc#1052095).

  - iwlwifi: missing error code in iwl_trans_pcie_alloc()
    (bsc#1031717).

  - kabi: arm64: compatibility workaround for lse atomics
    (bsc#1055290).

  - kABI: protect enum pid_type (kabi).

  - kABI: protect struct iscsi_np (kabi).

  - kABI: protect struct se_lun (kabi).

  - kabi/severities: add fs/ceph to kabi severities
    (bsc#1048228).

  - kabi/severities: Ignore drivers/scsi/cxgbi (bsc#1052094)

  - kabi/severities: Ignore kABI changes due to last
    patchset (bnc#1053472)

  - kABI: uninline task_tgid_nr_nr (kabi).

  - kvm: arm64: Restore host physical timer access on
    hyp_panic() (bsc#1054082).

  - kvm: arm/arm64: Fix bug in advertising KVM_CAP_MSI_DEVID
    capability (bsc#1054082).

  - kvm, pkeys: do not use PKRU value in
    vcpu->arch.guest_fpu.state (bsc#1055935).

  - kvm: x86: block guest protection keys unless the host
    has them enabled (bsc#1055935).

  - kvm: x86: kABI workaround for PKRU fixes (bsc#1055935).

  - kvm: x86: simplify handling of PKRU (bsc#1055935).

  - libceph: abort already submitted but abortable requests
    when map or pool goes full (bsc#1048228).

  - libceph: add an epoch_barrier field to struct
    ceph_osd_client (bsc#1048228).

  - libceph: advertise support for NEW_OSDOP_ENCODING and
    SERVER_LUMINOUS (bsc#1048228).

  - libceph: advertise support for OSD_POOLRESEND
    (bsc#1048228).

  - libceph: allow requests to return immediately on full
    conditions if caller wishes (bsc#1048228).

  - libceph: always populate t->target_(oid,oloc) in
    calc_target() (bsc#1048228).

  - libceph: always signal completion when done
    (bsc#1048228).

  - libceph: apply_upmap() (bsc#1048228).

  - libceph: avoid unnecessary pi lookups in calc_target()
    (bsc#1048228).

  - libceph: ceph_connection_operations::reencode_message()
    method (bsc#1048228).

  - libceph: ceph_decode_skip_* helpers (bsc#1048228).

  - libceph: compute actual pgid in
    ceph_pg_to_up_acting_osds() (bsc#1048228).

  - libceph, crush: per-pool crush_choose_arg_map for
    crush_do_rule() (bsc#1048228).

  - libceph: delete from need_resend_linger before
    check_linger_pool_dne() (bsc#1048228).

  - libceph: do not call encode_request_finish() on
    MOSDBackoff messages (bsc#1048228).

  - libceph: do not call ->reencode_message() more than once
    per message (bsc#1048228).

  - libceph: do not pass pgid by value (bsc#1048228).

  - libceph: drop need_resend from calc_target()
    (bsc#1048228).

  - libceph: encode_(pgid,oloc)() helpers (bsc#1048228).

  - libceph: fallback for when there isn't a pool-specific
    choose_arg (bsc#1048228).

  - libceph: fix old style declaration warnings
    (bsc#1048228).

  - libceph: foldreq->last_force_resend into
    ceph_osd_request_target (bsc#1048228).

  - libceph: get rid of ack vs commit (bsc#1048228).

  - libceph: handle non-empty dest in ceph_(oloc,oid)_copy()
    (bsc#1048228).

  - libceph: initialize last_linger_id with a large integer
    (bsc#1048228).

  - libceph: introduce and switch to decode_pg_mapping()
    (bsc#1048228).

  - libceph: introduce ceph_spg, ceph_pg_to_primary_shard()
    (bsc#1048228).

  - libceph: kill __(insert,lookup,remove)_pg_mapping()
    (bsc#1048228).

  - libceph: make DEFINE_RB_* helpers more general
    (bsc#1048228).

  - libceph: make encode_request_*() work with r_mempool
    requests (bsc#1048228).

  - libceph: make RECOVERY_DELETES feature create a new
    interval (bsc#1048228).

  - libceph: make sure need_resend targets reflect latest
    map (bsc#1048228).

  - libceph: MOSDOp v8 encoding (actual spgid + full hash)
    (bsc#1048228).

  - libceph: new features macros (bsc#1048228).

  - libceph: new pi->last_force_request_resend
    (bsc#1048228).

  - libceph: NULL deref on osdmap_apply_incremental() error
    path (bsc#1048228).

  - libceph: osd_request_timeout option (bsc#1048228).

  - libceph: osd_state is 32 bits wide in luminous
    (bsc#1048228).

  - libceph: pg_upmap[_items] infrastructure (bsc#1048228).

  - libceph: pool deletion detection (bsc#1048228).

  - libceph: potential NULL dereference in
    ceph_msg_data_create() (bsc#1048228).

  - libceph: remove ceph_sanitize_features() workaround
    (bsc#1048228).

  - libceph: remove now unused finish_request() wrapper
    (bsc#1048228).

  - libceph: remove req->r_replay_version (bsc#1048228).

  - libceph: resend on PG splits if OSD has RESEND_ON_SPLIT
    (bsc#1048228).

  - libceph: respect RADOS_BACKOFF backoffs (bsc#1048228).

  - libceph: set -EINVAL in one place in crush_decode()
    (bsc#1048228).

  - libceph: support SERVER_JEWEL feature bits
    (bsc#1048228).

  - libceph: take osdc->lock in osdmap_show() and dump flags
    in hex (bsc#1048228).

  - libceph: upmap semantic changes (bsc#1048228).

  - libceph: use alloc_pg_mapping() in
    __decode_pg_upmap_items() (bsc#1048228).

  - libceph: use target pi for calc_target() calculations
    (bsc#1048228).

  - lib: test_rhashtable: fix for large entry counts
    (bsc#1055359).

  - lib: test_rhashtable: Fix KASAN warning (bsc#1055359).

  - locking/rwsem: Fix down_write_killable() for
    CONFIG_RWSEM_GENERIC_SPINLOCK=y (bsc#969756).

  - locking/rwsem-spinlock: Fix EINTR branch in
    __down_write_common() (bsc#969756).

  - lpfc: Add Buffer to Buffer credit recovery support
    (bsc#1052384).

  - lpfc: convert info messages to standard messages
    (bsc#1052384).

  - lpfc: Correct issues with FAWWN and FDISCs
    (bsc#1052384).

  - lpfc: Correct return error codes to align with nvme_fc
    transport (bsc#1052384).

  - lpfc: Fix bad sgl reposting after 2nd adapter reset
    (bsc#1052384).

  - lpfc: Fix crash in lpfc nvmet when fc port is reset
    (bsc#1052384).

  - lpfc: Fix duplicate NVME rport entries and namespaces
    (bsc#1052384).

  - lpfc: Fix handling of FCP and NVME FC4 types in Pt2Pt
    topology (bsc#1052384).

  - lpfc: fix 'integer constant too large' error on 32bit
    archs (bsc#1052384).

  - lpfc: Fix loop mode target discovery (bsc#1052384).

  - lpfc: Fix MRQ > 1 context list handling (bsc#1052384).

  - lpfc: Fix NVME PRLI handling during RSCN (bsc#1052384).

  - lpfc: Fix nvme target failure after 2nd adapter reset
    (bsc#1052384).

  - lpfc: Fix oops when NVME Target is discovered in a
    nonNVME environment (bsc#1052384).

  - lpfc: Fix plogi collision that causes illegal state
    transition (bsc#1052384).

  - lpfc: Fix rediscovery on switch blade pull
    (bsc#1052384).

  - lpfc: Fix relative offset error on large nvmet target
    ios (bsc#1052384).

  - lpfc: fixup crash during storage failover operations
    (bsc#1042847).

  - lpfc: Limit amount of work processed in IRQ
    (bsc#1052384).

  - lpfc: lpfc version bump 11.4.0.3 (bsc#1052384).

  - lpfc: remove console log clutter (bsc#1052384).

  - lpfc: support nvmet_fc defer_rcv callback (bsc#1052384).

  - megaraid_sas: Fix probing cards without io port
    (bsc#1053681).

  - mmc: mmc: correct the logic for setting HS400ES signal
    voltage (bsc#1054082).

  - mm, madvise: ensure poisoned pages are removed from
    per-cpu lists (VM hw poison -- git fixes).

  - mptsas: Fixup device hotplug for VMware ESXi
    (bsc#1030850).

  - net: ethernet: hip04: Call SET_NETDEV_DEV()
    (bsc#1049336).

  - netfilter: fix IS_ERR_VALUE usage (bsc#1052888).

  - netfilter: x_tables: pack percpu counter allocations
    (bsc#1052888).

  - netfilter: x_tables: pass xt_counters struct instead of
    packet counter (bsc#1052888).

  - netfilter: x_tables: pass xt_counters struct to counter
    allocator (bsc#1052888).

  - net: hns: add acpi function of xge led control
    (bsc#1049336).

  - net: hns: Fix a skb used after free bug (bsc#1049336).

  - net/mlx5: Cancel delayed recovery work when unloading
    the driver (bsc#1015342).

  - net/mlx5: Clean SRIOV eswitch resources upon VF creation
    failure (bsc#1015342).

  - net/mlx5: Consider tx_enabled in all modes on remap
    (bsc#1015342).

  - net/mlx5e: Add field select to MTPPS register
    (bsc#1015342).

  - net/mlx5e: Add missing support for PTP_CLK_REQ_PPS
    request (bsc#1015342).

  - net/mlx5e: Change 1PPS out scheme (bsc#1015342).

  - net/mlx5e: Fix broken disable 1PPS flow (bsc#1015342).

  - net/mlx5e: Fix outer_header_zero() check size
    (bsc#1015342).

  - net/mlx5e: Fix TX carrier errors report in get stats ndo
    (bsc#1015342).

  - net/mlx5e: Initialize CEE's getpermhwaddr address buffer
    to 0xff (bsc#1015342).

  - net/mlx5e: Rename physical symbol errors counter
    (bsc#1015342).

  - net/mlx5: Fix mlx5_add_flow_rules call with correct num
    of dests (bsc#1015342).

  - net/mlx5: Fix mlx5_ifc_mtpps_reg_bits structure size
    (bsc#1015342).

  - net/mlx5: Fix offset of hca cap reserved field
    (bsc#1015342).

  - net: phy: Fix lack of reference count on PHY driver
    (bsc#1049336).

  - net: phy: Fix PHY module checks and NULL deref in
    phy_attach_direct() (bsc#1049336).

  - nvme-fc: address target disconnect race conditions in
    fcp io submit (bsc#1052384).

  - nvme-fc: do not override opts->nr_io_queues
    (bsc#1052384).

  - nvme-fc: kABI fix for defer_rcv() callback
    (bsc#1052384).

  - nvme_fc/nvmet_fc: revise Create Association descriptor
    length (bsc#1052384).

  - nvme_fc: Reattach to localports on re-registration
    (bsc#1052384).

  - nvme-fc: revise TRADDR parsing (bsc#1052384).

  - nvme-fc: update tagset nr_hw_queues after queues reinit
    (bsc#1052384).

  - nvme-fc: use blk_mq_delay_run_hw_queue instead of
    open-coding it (bsc#1052384).

  - nvme: fix hostid parsing (bsc#1049272).

  - nvme-loop: update tagset nr_hw_queues after
    reconnecting/resetting (bsc#1052384).

  - nvme-pci: fix CMB sysfs file removal in reset path
    (bsc#1050211).

  - nvme-rdma: update tagset nr_hw_queues after
    reconnecting/resetting (bsc#1052384).

  - nvmet: avoid unneeded assignment of submit_bio return
    value (bsc#1052384).

  - nvmet_fc: Accept variable pad lengths on Create
    Association LS (bsc#1052384).

  - nvmet_fc: add defer_req callback for deferment of cmd
    buffer return (bsc#1052384).

  - nvmet-fc: correct use after free on list teardown
    (bsc#1052384).

  - nvmet-fc: eliminate incorrect static markers on local
    variables (bsc#1052384).

  - nvmet-fc: fix byte swapping in
    nvmet_fc_ls_create_association (bsc#1052384).

  - nvmet_fc: Simplify sg list handling (bsc#1052384).

  - nvmet: prefix version configfs file with attr
    (bsc#1052384).

  - of: fix '/cpus' reference leak in
    of_numa_parse_cpu_nodes() (bsc#1056827).

  - ovl: fix dentry leak for default_permissions
    (bsc#1054084).

  - pci/msi: fix the pci_alloc_irq_vectors_affinity stub
    (bsc#1050211).

  - pci/MSI: Ignore affinity if pre/post vector count is
    more than min_vecs (1050211).

  - percpu_ref: allow operation mode switching operations to
    be called concurrently (bsc#1055096).

  - percpu_ref: remove unnecessary RCU grace period for
    staggered atomic switching confirmation (bsc#1055096).

  - percpu_ref: reorganize __percpu_ref_switch_to_atomic()
    and relocate percpu_ref_switch_to_atomic()
    (bsc#1055096).

  - percpu_ref: restructure operation mode switching
    (bsc#1055096).

  - percpu_ref: unify staggered atomic switching wait
    behavior (bsc#1055096).

  - phy: Do not increment MDIO bus refcount unless it's a
    different owner (bsc#1049336).

  - phy: fix error case of phy_led_triggers_(un)register
    (bsc#1049336).

  - qeth: add network device features for VLAN devices
    (bnc#1053472, LTC#157385).

  - r8169: Add support for restarting auto-negotiation
    (bsc#1050742).

  - r8169:Correct the way of setting RTL8168DP ephy
    (bsc#1050742).

  - r8169:fix system hange problem (bsc#1050742).

  - r8169:Fix typo in setting RTL8168H PHY parameter
    (bsc#1050742).

  - r8169:Fix typo in setting RTL8168H PHY PFM mode
    (bsc#1050742).

  - r8169:Remove unnecessary phy reset for pcie nic when
    setting link spped (bsc#1050742).

  - r8169:Update the way of reading RTL8168H PHY register
    'rg_saw_cnt' (bsc#1050742).

  - rdma/mlx5: Fix existence check for extended address
    vector (bsc#1015342).

  - Remove patch
    0407-nvme_fc-change-failure-code-on-remoteport-connectiv
    i.patch (bsc#1037838)

  - Revert 'ceph: SetPageError() for writeback pages if
    writepages fails' (bsc#1048228).

  - s390/diag: add diag26c support (bnc#1053472,
    LTC#156729).

  - s390: export symbols for crash-kmp (bsc#1053915).

  - s390: Include uapi/linux/if_ether.h instead of
    linux/if_ether.h (bsc#1053472).

  - s390/pci: do not cleanup in arch_setup_msi_irqs
    (bnc#1053472, LTC#157731).

  - s390/pci: fix handling of PEC 306 (bnc#1053472,
    LTC#157731).

  - s390/pci: improve error handling during fmb
    (de)registration (bnc#1053472, LTC#157731).

  - s390/pci: improve error handling during interrupt
    deregistration (bnc#1053472, LTC#157731).

  - s390/pci: improve pci hotplug (bnc#1053472, LTC#157731).

  - s390/pci: improve unreg_ioat error handling
    (bnc#1053472, LTC#157731).

  - s390/pci: introduce clp_get_state (bnc#1053472,
    LTC#157731).

  - s390/pci: provide more debug information (bnc#1053472,
    LTC#157731).

  - s390/pci: recognize name clashes with uids (bnc#1053472,
    LTC#157731).

  - s390/qeth: no ETH header for outbound AF_IUCV
    (bnc#1053472, LTC#156276).

  - s390/qeth: size calculation outbound buffers
    (bnc#1053472, LTC#156276).

  - s390/qeth: use diag26c to get MAC address on L2
    (bnc#1053472, LTC#156729).

  - scsi: csiostor: add check for supported fw version
    (bsc#1005776).

  - scsi: csiostor: add support for Chelsio T6 adapters
    (bsc#1005776).

  - scsi: csiostor: fix use after free in
    csio_hw_use_fwconfig() (bsc#1005776).

  - scsi: csiostor: switch to pci_alloc_irq_vectors
    (bsc#1005776).

  - scsi: csiostor: update module version (bsc#1052093).

  - scsi: cxgb4i: assign rxqs in round robin mode
    (bsc#1052094).

  - scsi: qedf: Fix a potential NULL pointer dereference
    (bsc#1048912).

  - scsi: qedf: Limit number of CQs (bsc#1040813).

  - supported.conf: clear mistaken external support flag for
    cifs.ko (bsc#1053802).

  - tpm: fix: return rc when devm_add_action() fails
    (bsc#1020645, fate#321435, fate#321507, fate#321600,
    bsc#1034048, git-fixes 8e0ee3c9faed).

  - tpm: Issue a TPM2_Shutdown for TPM2 devices
    (bsc#1053117).

  - tpm: KABI fix (bsc#1053117).

  - tpm: read burstcount from TPM_STS in one 32-bit
    transaction (bsc#1020645, fate#321435, fate#321507,
    fate#321600, bsc#1034048, git-fixes 27084efee0c3).

  - tpm_tis_core: Choose appropriate timeout for reading
    burstcount (bsc#1020645, fate#321435, fate#321507,
    fate#321600, bsc#1034048, git-fixes aec04cbdf723).

  - tpm_tis_core: convert max timeouts from msec to jiffies
    (bsc#1020645, fate#321435, fate#321507, fate#321600,
    bsc#1034048, git-fixes aec04cbdf723).

  - tty: pl011: fix initialization order of QDF2400 E44
    (bsc#1054082).

  - tty: serial: msm: Support more bauds (git-fixes).

  - Update
    patches.drivers/tpm-141-fix-RC-value-check-in-tpm2_seal_
    trusted.patch (bsc#1020645, fate#321435, fate#321507,
    fate#321600, bsc#1034048, git-fixes 5ca4c20cfd37).

  - usb: core: fix device node leak (bsc#1047487).

  - x86/mm: Fix use-after-free of ldt_struct (bsc#1055963).

  - xfs/dmapi: fix incorrect file->f_path.dentry->d_inode
    usage (bsc#1055896).

  - xfs: nowait aio support (FATE#321994).

  - xgene: Always get clk source, but ignore if it's missing
    for SGMII ports (bsc#1048501).

  - xgene: Do not fail probe, if there is no clk resource
    for SGMII interfaces (bsc#1048501)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969756"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.85-22.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.85-22.3") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.85-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.85-22.1") ) flag++;

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
