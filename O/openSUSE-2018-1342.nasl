#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1342.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118818);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-16533", "CVE-2017-18224", "CVE-2018-10940", "CVE-2018-16658", "CVE-2018-18386", "CVE-2018-18445", "CVE-2018-18710");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-1342)");
  script_summary(english:"Check for the openSUSE-2018-1342 patch");

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

  - CVE-2018-18710: An information leak in
    cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c could
    be used by local attackers to read kernel memory because
    a cast from unsigned long to int interferes with bounds
    checking. This is similar to CVE-2018-10940 and
    CVE-2018-16658 (bnc#1113751).

  - CVE-2018-18445: Faulty computation of numeric bounds in
    the BPF verifier permitted out-of-bounds memory accesses
    because adjust_scalar_min_max_vals in
    kernel/bpf/verifier.c mishandled 32-bit right shifts
    (bnc#1112372).

  - CVE-2018-18386: drivers/tty/n_tty.c allowed local
    attackers (who are able to access pseudo terminals) to
    hang/block further usage of any pseudo terminal devices
    due to an EXTPROC versus ICANON confusion in TIOCINQ
    (bnc#1094825).

  - CVE-2017-18224: fs/ocfs2/aops.c omitted use of a
    semaphore and consequently has a race condition for
    access to the extent tree during read operations in
    DIRECT mode, which allowed local users to cause a denial
    of service (BUG) by modifying a certain e_cpos field
    (bnc#1084831).

  - CVE-2017-16533: The usbhid_parse function in
    drivers/hid/usbhid/hid-core.c allowed local users to
    cause a denial of service (out-of-bounds read and system
    crash) or possibly have unspecified other impact via a
    crafted USB device (bnc#1066674).

The following non-security bugs were fixed :

  - acpi / processor: Fix the return value of
    acpi_processor_ids_walk() (bsc#1051510).

  - aio: fix io_destroy(2) vs. lookup_ioctx() race
    (git-fixes).

  - alsa: hda: Add 2 more models to the power_save blacklist
    (bsc#1051510).

  - alsa: hda - Add mic quirk for the Lenovo G50-30
    (17aa:3905) (bsc#1051510).

  - alsa: hda - Add quirk for ASUS G751 laptop
    (bsc#1051510).

  - alsa: hda - Fix headphone pin config for ASUS G751
    (bsc#1051510).

  - alsa: hda: fix unused variable warning (bsc#1051510).

  - alsa: hda/realtek - Fix the problem of the front MIC on
    the Lenovo M715 (bsc#1051510).

  - alsa: usb-audio: update quirk for B&W PX to remove
    microphone (bsc#1051510).

  - apparmor: Check buffer bounds when mapping permissions
    mask (git-fixes).

  - ASoC: intel: skylake: Add missing break in
    skl_tplg_get_token() (bsc#1051510).

  - ASoC: Intel: Skylake: Reset the controller in probe
    (bsc#1051510).

  - ASoC: rsnd: adg: care clock-frequency size
    (bsc#1051510).

  - ASoC: rsnd: do not fallback to PIO mode when
    -EPROBE_DEFER (bsc#1051510).

  - ASoC: rt5514: Fix the issue of the delay volume applied
    again (bsc#1051510).

  - ASoC: sigmadsp: safeload should not have lower byte
    limit (bsc#1051510).

  - ASoC: wm8804: Add ACPI support (bsc#1051510).

  - ath10k: fix kernel panic issue during pci probe
    (bsc#1051510).

  - ath10k: fix scan crash due to incorrect length
    calculation (bsc#1051510).

  - ath10k: fix use-after-free in ath10k_wmi_cmd_send_nowait
    (bsc#1051510).

  - batman-adv: Avoid probe ELP information leak
    (bsc#1051510).

  - batman-adv: fix backbone_gw refcount on queue_work()
    failure (bsc#1051510).

  - batman-adv: fix hardif_neigh refcount on queue_work()
    failure (bsc#1051510).

  - bdi: Fix another oops in wb_workfn() (bsc#1112746).

  - bdi: Preserve kabi when adding cgwb_release_mutex
    (bsc#1112746).

  - blkdev_report_zones_ioctl(): Use vmalloc() to allocate
    large buffers (bsc#1111819).

  - blk-mq: I/O and timer unplugs are inverted in blktrace
    (bsc#1112713).

  - block, bfq: fix wrong init of saved start time for
    weight raising (bsc#1112708).

  - block: bfq: swap puts in bfqg_and_blkg_put
    (bsc#1112712).

  - block: bvec_nr_vecs() returns value for wrong slab
    (bsc#1111834).

  - bpf/verifier: disallow pointer subtraction
    (bsc#1083647).

  - btrfs: Enhance btrfs_trim_fs function to handle error
    better (Dependency for bsc#1113667).

  - btrfs: Ensure btrfs_trim_fs can trim the whole
    filesystem (bsc#1113667).

  - btrfs: fix file data corruption after cloning a range
    and fsync (bsc#1111901).

  - btrfs: fix missing error return in btrfs_drop_snapshot
    (Git-fixes bsc#1109919).

  - btrfs: fix mount failure after fsync due to hard link
    recreation (bsc#1103543).

  - btrfs: handle errors while updating refcounts in
    update_ref_for_cow (Git-fixes bsc#1109915).

  - btrfs: send, fix invalid access to commit roots due to
    concurrent snapshotting (bsc#1111904).

  - cdc-acm: fix race between reset and control messaging
    (bsc#1051510).

  - ceph: avoid a use-after-free in ceph_destroy_options()
    (bsc#1111983).

  - cifs: check for STATUS_USER_SESSION_DELETED
    (bsc#1112902).

  - cifs: fix memory leak in SMB2_open() (bsc#1112894).

  - cifs: Fix use after free of a mid_q_entry (bsc#1112903).

  - clk: x86: add 'ether_clk' alias for Bay Trail / Cherry
    Trail (bsc#1051510).

  - clk: x86: Stop marking clocks as CLK_IS_CRITICAL
    (bsc#1051510).

  - clocksource/drivers/ti-32k: Add
    CLOCK_SOURCE_SUSPEND_NONSTOP flag for non-am43 SoCs
    (bsc#1051510).

  - clocksource/drivers/timer-atmel-pit: Properly handle
    error cases (bsc#1051510).

  - coda: fix 'kernel memory exposure attempt' in fsync
    (bsc#1051510).

  - crypto: caam - fix implicit casts in endianness helpers
    (bsc#1051510).

  - crypto: chelsio - Fix memory corruption in DMA Mapped
    buffers (bsc#1051510).

  - crypto: lrw - Fix out-of bounds access on counter
    overflow (bsc#1051510).

  - crypto: tcrypt - fix ghash-generic speed test
    (bsc#1051510).

  - dax: Fix deadlock in dax_lock_mapping_entry()
    (bsc#1109951).

  - debugobjects: Make stack check warning more informative
    (bsc#1051510).

  - documentation/l1tf: Fix small spelling typo
    (bsc#1051510).

  - drm/amdgpu: Fix SDMA HQD destroy error on gfx_v7
    (bsc#1051510).

  - drm/amdgpu: Fix vce work queue was not cancelled when
    suspend (bsc#1106110)

  - drm/amdgpu/powerplay: fix missing break in switch
    statements (bsc#1113722)

  - drm/edid: VSDB yCBCr420 Deep Color mode bit definitions
    (bsc#1051510).

  - drm/hisilicon: hibmc: Do not carry error code in HiBMC
    framebuffer (bsc#1113722)

  - drm/hisilicon: hibmc: Do not overwrite fb helper surface
    depth (bsc#1113722)

  - drm/i915/audio: Hook up component bindings even if
    displays are (bsc#1113722)

  - drm/i915/dp: Link train Fallback on eDP only if fallback
    link BW can fit panel's native mode (bsc#1051510).

  - drm/i915/gen9+: Fix initial readout for Y tiled
    framebuffers (bsc#1113722)

  - drm/i915/glk: Add Quirk for GLK NUC HDMI port issues
    (bsc#1051510).

  - drm/i915: Restore vblank interrupts earlier
    (bsc#1051510).

  - drm: mali-dp: Call drm_crtc_vblank_reset on device init
    (bsc#1051510).

  - drm/mediatek: fix OF sibling-node lookup (bsc#1106110)

  - drm/msm: fix OF child-node lookup (bsc#1106110)

  - drm/nouveau: Do not disable polling in fallback mode
    (bsc#1103356).

  - drm/sti: do not remove the drm_bridge that was never
    added (bsc#1100132)

  - drm/sun4i: Fix an ulong overflow in the dotclock driver
    (bsc#1106110)

  - drm/virtio: fix bounds check in
    virtio_gpu_cmd_get_capset() (bsc#1113722)

  - e1000: check on netif_running() before calling
    e1000_up() (bsc#1051510).

  - e1000: ensure to free old tx/rx rings in set_ringparam()
    (bsc#1051510).

  - eeprom: at24: change nvmem stride to 1 (bsc#1051510).

  - eeprom: at24: check at24_read/write arguments
    (bsc#1051510).

  - eeprom: at24: correctly set the size for at24mac402
    (bsc#1051510).

  - enic: do not call enic_change_mtu in enic_probe
    (bsc#1051510).

  - enic: handle mtu change for vf properly (bsc#1051510).

  - enic: initialize enic->rfs_h.lock in enic_probe
    (bsc#1051510).

  - ethtool: fix a privilege escalation bug (bsc#1076830).

  - ext2, dax: set ext2_dax_aops for dax files
    (bsc#1112554).

  - ext4: avoid arithemetic overflow that can trigger a BUG
    (bsc#1112736).

  - ext4: avoid divide by zero fault when deleting corrupted
    inline directories (bsc#1112735).

  - ext4: check for NUL characters in extended attribute's
    name (bsc#1112732).

  - ext4: check to make sure the rename(2)'s destination is
    not freed (bsc#1112734).

  - ext4: do not mark mmp buffer head dirty (bsc#1112743).

  - ext4: fix online resize's handling of a too-small final
    block group (bsc#1112739).

  - ext4: fix online resizing for bigalloc file systems with
    a 1k block size (bsc#1112740).

  - ext4: fix spectre gadget in ext4_mb_regular_allocator()
    (bsc#1112733).

  - ext4: recalucate superblock checksum after updating free
    blocks/inodes (bsc#1112738).

  - ext4: reset error code in ext4_find_entry in fallback
    (bsc#1112731).

  - ext4: show test_dummy_encryption mount option in
    /proc/mounts (bsc#1112741).

  - fbdev/omapfb: fix omapfb_memory_read infoleak
    (bsc#1051510).

  - fs/quota: Fix spectre gadget in do_quotactl
    (bsc#1112745).

  - hfsplus: do not return 0 when fill_super() failed
    (bsc#1051510).

  - hfsplus: stop workqueue when fill_super() failed
    (bsc#1051510).

  - hfs: prevent crash on exit from failed search
    (bsc#1051510).

  - hid: hid-sensor-hub: Force logical minimum to 1 for
    power and report state (bsc#1051510).

  - hid: quirks: fix support for Apple Magic Keyboards
    (bsc#1051510).

  - hid: sensor-hub: Restore fixup for Lenovo ThinkPad Helix
    2 sensor hub report (bsc#1051510).

  - hv: avoid crash in vmbus sysfs files (bnc#1108377).

  - hv_netvsc: fix schedule in RCU context ().

  - hwrng: core - document the quality field (bsc#1051510).

  - hypfs_kill_super(): deal with failed allocations
    (bsc#1051510).

  - i2c: i2c-scmi: fix for i2c_smbus_write_block_data
    (bsc#1051510).

  - i2c: rcar: cleanup DMA for all kinds of failure
    (bsc#1051510).

  - iio: adc: at91: fix acking DRDY irq on simple
    conversions (bsc#1051510).

  - iio: adc: at91: fix wrong channel number in triggered
    buffer mode (bsc#1051510).

  - iio: adc: imx25-gcq: Fix leak of device_node in
    mx25_gcq_setup_cfgs() (bsc#1051510).

  - input: atakbd - fix Atari CapsLock behaviour
    (bsc#1051510).

  - input: atakbd - fix Atari keymap (bsc#1051510).

  - intel_th: pci: Add Ice Lake PCH support (bsc#1051510).

  - iommu/arm-smmu: Error out only if not enough context
    interrupts (bsc#1106237).

  - iommu/vt-d: Add definitions for PFSID (bsc#1106237).

  - iommu/vt-d: Fix dev iotlb pfsid use (bsc#1106237).

  - iommu/vt-d: Fix scatterlist offset handling
    (bsc#1106237).

  - iwlwifi: dbg: do not crash if the firmware crashes in
    the middle of a debug dump (bsc#1051510).

  - iwlwifi: mvm: Allow TKIP for AP mode (bsc#1051510).

  - iwlwifi: mvm: check for n_profiles validity in EWRD ACPI
    (bsc#1051510).

  - iwlwifi: mvm: clear HW_RESTART_REQUESTED when stopping
    the interface (bsc#1051510).

  - iwlwifi: mvm: open BA session only when sta is
    authorized (bsc#1051510).

  - iwlwifi: mvm: send BCAST management frames to the right
    station (bsc#1051510).

  - iwlwifi: pcie: gen2: build A-MSDU only for GSO
    (bsc#1051510).

  - iwlwifi: pcie gen2: check iwl_pcie_gen2_set_tb() return
    value (bsc#1051510).

  - jbd2: fix use after free in jbd2_log_do_checkpoint()
    (bsc#1113257).

  - kABI: Hide get_msr_feature() in kvm_x86_ops
    (bsc#1106240).

  - Kbuild: fix # escaping in .cmd files for future Make
    (git-fixes).

  - kernfs: update comment about kernfs_path() return value
    (bsc#1051510).

  - kprobes/x86: Fix %p uses in error messages
    (bsc#1110006).

  - ksm: fix unlocked iteration over vmas in
    cmp_and_merge_page() (VM Functionality bsc#1111806).

  - kvm: Make VM ioctl do valloc for some archs
    (bsc#1111506).

  - kvm: SVM: Add MSR-based feature support for serializing
    LFENCE (bsc#1106240).

  - kvm: VMX: support MSR_IA32_ARCH_CAPABILITIES as a
    feature MSR (bsc#1106240).

  - kvm: VMX: Tell the nested hypervisor to skip L1D flush
    on vmentry (bsc#1106240).

  - kvm: x86: Add a framework for supporting MSR-based
    features (bsc#1106240).

  - kvm: x86: define SVM/VMX specific
    kvm_arch_[alloc|free]_vm (bsc#1111506).

  - kvm: X86: Introduce kvm_get_msr_feature() (bsc#1106240).

  - kvm/x86: kABI fix for vm_alloc/vm_free changes
    (bsc#1111506).

  - kvm: x86: Set highest physical address bits in
    non-present/reserved SPTEs (bsc#1106240).

  - libertas: call into generic suspend code before turning
    off power (bsc#1051510).

  - libnvdimm, dimm: Maximize label transfer size
    (bsc#1111921, bsc#1113408, bsc#1113972).

  - libnvdimm, label: change nvdimm_num_label_slots per UEFI
    2.7 (bsc#1111921, bsc#1113408, bsc#1113972).

  - libnvdimm, label: Fix sparse warning (bsc#1111921,
    bsc#1113408, bsc#1113972).

  - lib/ubsan: add type mismatch handler for new GCC/Clang
    (bsc#1051510).

  - lib/ubsan.c: s/missaligned/misaligned/ (bsc#1051510).

  - loop: add recursion validation to LOOP_CHANGE_FD
    (bsc#1112711).

  - loop: do not call into filesystem while holding
    lo_ctl_mutex (bsc#1112710).

  - loop: fix LOOP_GET_STATUS lock imbalance (bsc#1113284).

  - mac80211: minstrel: fix using short preamble CCK rates
    on HT clients (bsc#1051510).

  - mach64: detect the dot clock divider correctly on sparc
    (bsc#1051510).

  - media: af9035: prevent buffer overflow on write
    (bsc#1051510).

  - media: cx231xx: fix potential sign-extension overflow on
    large shift (bsc#1051510).

  - media: dvb: fix compat ioctl translation (bsc#1051510).

  - media: em28xx: fix input name for Terratec AV 350
    (bsc#1051510).

  - media: em28xx: use a default format if TRY_FMT fails
    (bsc#1051510).

  - media: pci: cx23885: handle adding to list failure
    (bsc#1051510).

  - media: tvp5150: avoid going past array on
    v4l2_querymenu() (bsc#1051510).

  - media: tvp5150: fix switch exit in set control handler
    (bsc#1051510).

  - media: tvp5150: fix width alignment during
    set_selection() (bsc#1051510).

  - media: uvcvideo: Fix uvc_alloc_entity() allocation
    alignment (bsc#1051510).

  - media: v4l2-tpg: fix kernel oops when enabling HFLIP and
    OSD (bsc#1051510).

  - media: vsp1: Fix YCbCr planar formats pitch calculation
    (bsc#1051510).

  - mfd: arizona: Correct calling of runtime_put_sync
    (bsc#1051510).

  - mmc: block: avoid multiblock reads for the last sector
    in SPI mode (bsc#1051510).

  - mm: fix BUG_ON() in vmf_insert_pfn_pud() from
    VM_MIXEDMAP removal (bsc#1111841).

  - mm/migrate: Use spin_trylock() while resetting rate
    limit ().

  - mm: /proc/pid/pagemap: hide swap entries from
    unprivileged users (Git-fixes bsc#1109907).

  - move changes without Git-commit out of sorted section

  - nfc: nfcmrvl_uart: fix OF child-node lookup
    (bsc#1051510).

  - nfs: Avoid quadratic search when freeing delegations
    (bsc#1084760).

  - nvdimm: Clarify comment in sizeof_namespace_index
    (bsc#1111921, bsc#1113408, bsc#1113972).

  - nvdimm: Remove empty if statement (bsc#1111921,
    bsc#1113408, bsc#1113972).

  - nvdimm: Sanity check labeloff (bsc#1111921, bsc#1113408,
    bsc#1113972).

  - nvdimm: Split label init out from the logic for getting
    config data (bsc#1111921, bsc#1113408, bsc#1113972).

  - nvdimm: Use namespace index data to reduce number of
    label reads needed (bsc#1111921, bsc#1113408,
    bsc#1113972).

  - of: add helper to lookup compatible child node
    (bsc#1106110)

  - orangefs: fix deadlock; do not write i_size in read_iter
    (bsc#1051510).

  - orangefs: initialize op on loop restart in
    orangefs_devreq_read (bsc#1051510).

  - orangefs_kill_sb(): deal with allocation failures
    (bsc#1051510).

  - orangefs: use list_for_each_entry_safe in
    purge_waiting_ops (bsc#1051510).

  - ovl: fix format of setxattr debug (git-fixes).

  - ovl: Sync upper dirty data when syncing overlayfs
    (git-fixes).

  - pci/ASPM: Fix link_state teardown on device removal
    (bsc#1051510).

  - pci: hv: Do not wait forever on a device that has
    disappeared (bsc#1109806).

  - pci: Reprogram bridge prefetch registers on resume
    (bsc#1051510).

  - powerpc/mm/hugetlb: initialize the pagetable cache
    correctly for hugetlb (bsc#1091800).

  - powerpc/powernv/ioda2: Reduce upper limit for DMA window
    size (bsc#1055120).

  - powerpc/pseries: Fix build break for SPLPAR=n and CPU
    hotplug (bsc#1079524, git-fixes).

  - powerpc/pseries: Fix CONFIG_NUMA=n build (bsc#1067906,
    git-fixes).

  - powerpc/pseries: Fix 'OF: ERROR: Bad of_node_put() on
    /cpus' during DLPAR (bsc#1113295).

  - powerpc: pseries: remove dlpar_attach_node dependency on
    full path (bsc#1113295).

  - powerpc/rtas: Fix a potential race between CPU-Offline &
    Migration (bsc#1111870).

  - printk: drop in_nmi check from
    printk_safe_flush_on_panic() (bsc#1112170).

  - printk/tracing: Do not trace printk_nmi_enter()
    (bsc#1112208).

  - proc: restrict kernel stack dumps to root (git-fixes).
    blacklist.conf :

  - qmi_wwan: Added support for Gemalto's Cinterion ALASxx
    WWAN interface (bsc#1051510).

  - qrtr: add MODULE_ALIAS macro to smd (bsc#1051510).

  - r8169: Clear RTL_FLAG_TASK_*_PENDING when clearing
    RTL_FLAG_TASK_ENABLED (bsc#1051510).

  - random: rate limit unseeded randomness warnings
    (git-fixes).

  - rculist: add list_for_each_entry_from_rcu()
    (bsc#1084760).

  - rculist: Improve documentation for
    list_for_each_entry_from_rcu() (bsc#1084760).

  - reiserfs: add check to detect corrupted directory entry
    (bsc#1109818).

  - reiserfs: do not panic on bad directory entries
    (bsc#1109818).

  - scsi: core: Allow state transitions from OFFLINE to
    BLOCKED (bsc#1112246).

  - scsi: ipr: Eliminate duplicate barriers ().

  - scsi: ipr: fix incorrect indentation of assignment
    statement ().

  - scsi: ipr: Use dma_pool_zalloc() ().

  - scsi: libfc: check fc_frame_payload_get() return value
    for null (bsc#1104731).

  - scsi: libfc: retry PRLI if we cannot analyse the payload
    (bsc#1104731).

  - scsi: qla2xxx: Fix memory leak for allocating abort IOCB
    (bsc#1111830).

  - scsi: target: prefer dbroot of /etc/target over
    /var/target (bsc#1111928).

  - serial: 8250: Fix clearing FIFOs in RS485 mode again
    (bsc#1051510).

  - series.conf: moved some Xen patches to the sorted region
    xen/blkfront: correct purging of persistent grants
    (bnc#1112514).

  - signal: Properly deliver SIGSEGV from x86 uprobes
    (bsc#1110006).

  - smb2: fix missing files in root share directory listing
    (bsc#1112907).

  - smb3: fill in statfs fsid and correct namelen
    (bsc#1112905).

  - smb3: fix reset of bytes read and written stats
    (bsc#1112906).

  - smb3: on reconnect set PreviousSessionId field
    (bsc#1112899).

  - sock_diag: fix use-after-free read in __sk_free
    (bsc#1051510).

  - soc/tegra: pmc: Fix child-node lookup (bsc#1051510).

  - sound: do not call skl_init_chip() to reset intel skl
    soc (bsc#1051510).

  - sound: enable interrupt after dma buffer initialization
    (bsc#1051510).

  - spi/bcm63xx-hsspi: keep pll clk enabled (bsc#1051510).

  - spi: bcm-qspi: switch back to reading flash using
    smaller chunks (bsc#1051510).

  - spi: sh-msiof: fix deferred probing (bsc#1051510).

  - squashfs: more metadata hardening (bsc#1051510).

  - staging: comedi: ni_mio_common: protect register write
    overflow (bsc#1051510).

  - stm: Potential read overflow in
    stm_char_policy_set_ioctl() (bsc#1051510).

  - switchtec: Fix Spectre v1 vulnerability (bsc#1051510).

  - sysfs: Do not return POSIX ACL xattrs via listxattr
    (git-fixes).

  - target: log Data-Out timeouts as errors (bsc#1095805).

  - target: log NOP ping timeouts as errors (bsc#1095805).

  - target: split out helper for cxn timeout error stashing
    (bsc#1095805).

  - target: stash sess_err_stats on Data-Out timeout
    (bsc#1095805).

  - target: use ISCSI_IQN_LEN in iscsi_target_stat
    (bsc#1095805).

  - team: Forbid enslaving team device to itself
    (bsc#1051510).

  - tools build: fix # escaping in .cmd files for future
    Make (git-fixes).

  - tools/vm/page-types.c: fix 'defined but not used'
    warning (bsc#1051510).

  - tools/vm/slabinfo.c: fix sign-compare warning
    (bsc#1051510).

  - tracing: Add barrier to trace_printk() buffer nesting
    modification (bsc#1112219).

  - tty: fix data race between tty_init_dev and flush of buf
    (bnc#1105428).

  - tty: Hold tty_ldisc_lock() during tty_reopen()
    (bnc#1105428).

  - tty/ldsem: Add lockdep asserts for ldisc_sem
    (bnc#1105428).

  - tty/ldsem: Convert to regular lockdep annotations
    (bnc#1105428).

  - tty/ldsem: Decrement wait_readers on timeouted
    down_read() (bnc#1105428).

  - tty/ldsem: Wake up readers after timed out down_write()
    (bnc#1105428).

  - tty: Simplify tty->count math in tty_reopen()
    (bnc#1105428).

  - usb: chipidea: Prevent unbalanced IRQ disable
    (bsc#1051510).

  - usb: gadget: fotg210-udc: Fix memory leak of
    fotg210->ep[i] (bsc#1051510).

  - usb: gadget: fsl_udc_core: check allocation return value
    and cleanup on failure (bsc#1051510).

  - usb: gadget: fsl_udc_core: fixup struct_udc_setup
    documentation (bsc#1051510).

  - usbip: tools: fix atoi() on non-null terminated string
    (bsc#1051510).

  - usb: remove LPM management from
    usb_driver_claim_interface() (bsc#1051510).

  - usb: serial: cypress_m8: fix interrupt-out transfer
    length (bsc#1051510).

  - usb: serial: simple: add Motorola Tetra MTP6550 id
    (bsc#1051510).

  - usb: xhci-mtk: resume USB3 roothub first (bsc#1051510).

  - usb: yurex: Check for truncation in yurex_read()
    (bsc#1051510).

  - userfaultfd: hugetlbfs: fix userfaultfd_huge_must_wait()
    pte access (bsc#1109739).

  - Use upstream version of pci-hyperv patch (35a88a1)

  - vmbus: do not return values for uninitalized channels
    (bsc#1051510).

  - vti4: Do not count header length twice on tunnel setup
    (bsc#1051510).

  - vti6: fix PMTU caching and reporting on xmit
    (bsc#1051510).

  - vti6: remove !skb->ignore_df check from vti6_xmit()
    (bsc#1051510).

  - Workaround for mysterious NVMe breakage with i915 CFL
    (bsc#1111040).

  - x86/acpi: Prevent X2APIC id 0xffffffff from being
    accounted (bsc#1110006).

  - x86/boot/KASLR: Work around firmware bugs by excluding
    EFI_BOOT_SERVICES_* and EFI_LOADER_* from KASLR's choice
    (bnc#1112878).

  - x86/boot: Move EISA setup to a separate file
    (bsc#1110006).

  - x86/cpufeature: Add User-Mode Instruction Prevention
    definitions (bsc#1110006).

  - x86/cpufeatures: Add Intel Total Memory Encryption
    cpufeature (bsc#1110006).

  - x86/eisa: Add missing include (bsc#1110006).

  - x86/EISA: Do not probe EISA bus for Xen PV guests
    (bsc#1110006).

  - x86/fpu: Remove second definition of fpu in
    __fpu__restore_sig() (bsc#1110006).

  - x86/kasan: Panic if there is not enough memory to boot
    (bsc#1110006).

  - x86/MCE: Fix stack out-of-bounds write in mce-inject.c:
    Flags_read() (bsc#1110006).

  - x86/paravirt: Fix some warning messages (bnc#1065600).

  - x86/percpu: Fix this_cpu_read() (bsc#1110006).

  - x86/speculation/l1tf: Fix overflow in l1tf_pfn_limit()
    on 32bit (bsc#1105536).

  - x86/time: Correct the attribute on jiffies' definition
    (bsc#1110006).

  - xen/gntdev: avoid out of bounds access in case of
    partial gntdev_mmap() (bnc#1065600).

  - xen: Remove unnecessary BUG_ON from __unbind_from_irq()
    (bnc#1065600).

  - xen-swiotlb: fix the check condition for
    xen_swiotlb_free_coherent (bnc#1065600).

  - xfrm: use complete IPv6 addresses for hash
    (bsc#1109330).

  - xfs: do not fail when converting shortform attr to long
    form during ATTR_REPLACE (bsc#1105025).

  - xhci: Add missing CAS workaround for Intel Sunrise Point
    xHCI (bsc#1051510).

  - xhci: Do not print a warning when setting link state for
    disabled ports (bsc#1051510)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113972"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.25.1") ) flag++;

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
