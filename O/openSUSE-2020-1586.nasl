#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1586.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141161);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-14385", "CVE-2020-14390", "CVE-2020-2521", "CVE-2020-25284", "CVE-2020-26088");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1586)");
  script_summary(english:"Check for the openSUSE-2020-1586 patch");

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

  - CVE-2020-0404: In uvc_scan_chain_forward of
    uvc_driver.c, there is a possible linked list corruption
    due to an unusual root cause. This could lead to local
    escalation of privilege in the kernel with no additional
    execution privileges needed. User interaction is not
    needed for exploitation (bnc#1176423).

  - CVE-2020-0427: In create_pinctrl of core.c, there is a
    possible out of bounds read due to a use after free.
    This could lead to local information disclosure with no
    additional execution privileges needed. User interaction
    is not needed for exploitation (bnc#1176725).

  - CVE-2020-0431: In kbd_keycode of keyboard.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation
    (bnc#1176722).

  - CVE-2020-0432: In skb_to_mamac of networking.c, there is
    a possible out of bounds write due to an integer
    overflow. This could lead to local escalation of
    privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation
    (bnc#1176721).

  - CVE-2020-14385: Fixed a boundary test in
    xfs_attr_shortform_verify which could lead to crashes
    (bsc#1176137).

  - CVE-2020-14390: When changing screen size, an
    out-of-bounds memory write can occur leading to memory
    corruption or a denial of service. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled out
    (bnc#1176235).

  - CVE-2020-2521: Fixed a getxattr kernel panic and memory
    overflow in NFS4(bsc#1176381).

  - CVE-2020-25284: Require global CAP_SYS_ADMIN for mapping
    and unmapping rbd devices (bsc#1176543).

  - CVE-2020-26088: A missing CAP_NET_RAW check in NFC
    socket creation in net/nfc/rawsock.c could be used by
    local attackers to create raw sockets, bypassing
    security mechanisms, aka CID-26896f01467a (bnc#1176990).

The following non-security bugs were fixed :

  - ALSA: asihpi: fix iounmap in error handler (git-fixes).

  - ALSA: ca0106: fix error code handling (git-fixes).

  - ALSA: firewire-digi00x: exclude Avid Adrenaline from
    detection (git-fixes).

  - ALSA; firewire-tascam: exclude Tascam FE-8 from
    detection (git-fixes).

  - ALSA: hda: Fix 2 channel swapping for Tegra (git-fixes).

  - ALSA: hda: fix a runtime pm issue in SOF when integrated
    GPU is disabled (git-fixes).

  - ALSA: hda - Fix silent audio output and corrupted input
    on MSI X570-A PRO (git-fixes).

  - ALSA: hda: fixup headset for ASUS GX502 laptop
    (git-fixes).

  - ALSA: hda: hdmi - add Rocketlake support (git-fixes).

  - ALSA: hda/hdmi: always check pin power status in i915
    pin fixup (git-fixes).

  - ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion
    NT950XCJ-X716A (git-fixes).

  - ALSA: hda/realtek - Couldn't detect Mic if booting with
    headset plugged (git-fixes).

  - ALSA: hda/realtek: Enable front panel headset LED on
    Lenovo ThinkStation P520 (git-fixes).

  - ALSA: hda/realtek - Improved routing for Thinkpad X1
    7th/8th Gen (git-fixes).

  - ALSA: hda/realtek - The Mic on a RedmiBook does not work
    (git-fixes).

  - ALSA: hda/tegra: Program WAKEEN register for Tegra
    (git-fixes).

  - ALSA: pcm: oss: Remove superfluous WARN_ON() for mulaw
    sanity check (git-fixes).

  - ALSA: usb-audio: Add basic capture support for Pioneer
    DJ DJM-250MK2 (git-fixes).

  - ALSA: usb-audio: Add delay quirk for H570e USB headsets
    (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for UR22C
    (git-fixes).

  - ALSA: usb-audio: Disable autosuspend for Lenovo
    ThinkStation P620 (git-fixes).

  - arm64: paravirt: Initialize steal time when cpu is
    online (bsc#1176833).

  - ASoC: img: Fix a reference count leak in
    img_i2s_in_set_fmt (git-fixes).

  - ASoC: img-parallel-out: Fix a reference count leak
    (git-fixes).

  - ASoC: meson: axg-toddr: fix channel order on g12
    platforms (git-fixes).

  - ASoC: qcom: common: Fix refcount imbalance on error
    (git-fixes).

  - ASoC: qcom: Set card->owner to avoid warnings
    (git-fixes).

  - ASoC: SOF: Intel: add PCI ID for CometLake-S
    (git-fixes).

  - ASoC: tegra: Fix reference count leaks (git-fixes).

  - ata: ahci: use ata_link_info() instead of
    ata_link_printk() (jsc#SLE-14459).

  - batman-adv: Add missing include for in_interrupt()
    (git-fixes).

  - batman-adv: Avoid uninitialized chaddr when handling
    DHCP (git-fixes).

  - batman-adv: bla: fix type misuse for backbone_gw hash
    indexing (git-fixes).

  - batman-adv: bla: use netif_rx_ni when not in interrupt
    context (git-fixes).

  - batman-adv: Fix own OGM check in aggregated OGMs
    (git-fixes).

  - batman-adv: mcast: fix duplicate mcast packets from BLA
    backbone to mesh (git-fixes).

  - batman-adv: mcast: fix duplicate mcast packets in BLA
    backbone from LAN (git-fixes).

  - batman-adv: mcast: fix duplicate mcast packets in BLA
    backbone from mesh (git-fixes).

  - batman-adv: mcast/TT: fix wrongly dropped or rerouted
    packets (git-fixes).

  - bcache: allocate meta data pages as compound pages
    (bsc#1172873).

  - bcache: Convert pr_<level> uses to a more typical style
    (git fixes (block drivers)).

  - bitfield.h: do not compile-time validate _val in
    FIELD_FIT (git fixes (bitfield)).

  - blktrace: fix debugfs use after free (git fixes (block
    drivers)).

  - block: add docs for gendisk / request_queue refcount
    helpers (git fixes (block drivers)).

  - block: check queue's limits.discard_granularity in
    __blkdev_issue_discard() (bsc#1152148).

  - block: improve discard bio alignment in
    __blkdev_issue_discard() (bsc#1152148).

  - block: revert back to synchronous request_queue removal
    (git fixes (block drivers)).

  - block: Use non _rcu version of list functions for
    tag_set_list (git-fixes).

  - bluetooth: btrtl: Add support for RTL8761B
    (bsc#1177021).

  - bnxt: do not enable NAPI until rings are ready
    (git-fixes).

  - bnxt_en: Check for zero dir entries in NVRAM
    (git-fixes).

  - bnxt_en: Do not query FW when netif_running() is false
    (git-fixes).

  - bnxt_en: Fix completion ring sizing with TPA enabled
    (networking-stable-20_07_29).

  - bnxt_en: fix HWRM error when querying VF temperature
    (git-fixes).

  - bnxt_en: Fix PCI AER error recovery flow (git-fixes).

  - bnxt_en: Fix possible crash in bnxt_fw_reset_task()
    (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Fix race when modifying pause settings
    (networking-stable-20_07_29).

  - bonding: check error value of register_netdevice()
    immediately (networking-stable-20_07_29).

  - bonding: check return value of register_netdevice() in
    bond_newlink() (networking-stable-20_07_29).

  - bonding: fix a potential double-unregister (git-fixes).

  - bpf: Fix a rcu warning for bpffs map pretty-print
    (bsc#1155518).

  - bpf: map_seq_next should always increase position index
    (bsc#1155518).

  - btrfs: add a leak check for roots (bsc#1176019).

  - btrfs: add __cold attribute to more functions
    (bsc#1176019).

  - btrfs: add dedicated members for start and length of a
    block group (bsc#1176019).

  - btrfs: Add read_backup_root (bsc#1176019).

  - btrfs: block-group: Refactor btrfs_read_block_groups()
    (bsc#1176019).

  - btrfs: block-group: Reuse the item key from caller of
    read_one_block_group() (bsc#1176019).

  - btrfs: Cleanup and simplify find_newest_super_backup
    (bsc#1176019).

  - btrfs: clear DEAD_RELOC_TREE before dropping the reloc
    root (bsc#1176019).

  - btrfs: do not init a reloc root if we are not relocating
    (bsc#1176019).

  - btrfs: Do not use objectid_mutex during mount
    (bsc#1176019).

  - btrfs: drop block from cache on error in relocation
    (bsc#1176019).

  - btrfs: drop create parameter to btrfs_get_extent()
    (bsc#1176019).

  - btrfs: drop unused parameter is_new from btrfs_iget
    (bsc#1176019).

  - btrfs: export and rename free_fs_info (bsc#1176019).

  - btrfs: export and use btrfs_read_tree_root for tree-log
    (bsc#1176019).

  - btrfs: Factor out tree roots initialization during mount
    (bsc#1176019).

  - btrfs: fix setting last_trans for reloc roots
    (bsc#1176019).

  - btrfs: free more things in btrfs_free_fs_info
    (bsc#1176019).

  - btrfs: free the reloc_control in a consistent way
    (bsc#1176019).

  - btrfs: handle NULL roots in btrfs_put/btrfs_grab_fs_root
    (bsc#1176019).

  - btrfs: hold a ref for the root in
    btrfs_find_orphan_roots (bsc#1176019).

  - btrfs: hold a ref on fs roots while they're in the radix
    tree (bsc#1176019).

  - btrfs: hold a ref on the root in
    btrfs_check_uuid_tree_entry (bsc#1176019).

  - btrfs: hold a ref on the root in
    btrfs_ioctl_get_subvol_info (bsc#1176019).

  - btrfs: hold a ref on the root in btrfs_ioctl_send
    (bsc#1176019).

  - btrfs: hold a ref on the root in btrfs_recover_log_trees
    (bsc#1176019).

  - btrfs: hold a ref on the root in
    btrfs_recover_relocation (bsc#1176019).

  - btrfs: hold a ref on the root in
    __btrfs_run_defrag_inode (bsc#1176019).

  - btrfs: hold a ref on the root in
    btrfs_search_path_in_tree (bsc#1176019).

  - btrfs: hold a ref on the root in
    btrfs_search_path_in_tree_user (bsc#1176019).

  - btrfs: hold a ref on the root in build_backref_tree
    (bsc#1176019).

  - btrfs: hold a ref on the root in create_pending_snapshot
    (bsc#1176019).

  - btrfs: hold a ref on the root in create_reloc_inode
    (bsc#1176019).

  - btrfs: hold a ref on the root in create_subvol
    (bsc#1176019).

  - btrfs: hold a ref on the root in find_data_references
    (bsc#1176019).

  - btrfs: hold a ref on the root in
    fixup_tree_root_location (bsc#1176019).

  - btrfs: hold a ref on the root in
    get_subvol_name_from_objectid (bsc#1176019).

  - btrfs: hold a ref on the root in merge_reloc_roots
    (bsc#1176019).

  - btrfs: hold a ref on the root in open_ctree
    (bsc#1176019).

  - btrfs: hold a ref on the root in prepare_to_merge
    (bsc#1176019).

  - btrfs: hold a ref on the root in
    record_reloc_root_in_trans (bsc#1176019).

  - btrfs: hold a ref on the root in resolve_indirect_ref
    (bsc#1176019).

  - btrfs: hold a ref on the root in
    scrub_print_warning_inode (bsc#1176019).

  - btrfs: hold a ref on the root in search_ioctl
    (bsc#1176019).

  - btrfs: hold a ref on the root->reloc_root (bsc#1176019).

  - btrfs: hold a root ref in btrfs_get_dentry
    (bsc#1176019).

  - btrfs: hold ref on root in btrfs_ioctl_default_subvol
    (bsc#1176019).

  - btrfs: implement full reflink support for inline extents
    (bsc#1176019).

  - btrfs: make btrfs_find_orphan_roots use
    btrfs_get_fs_root (bsc#1176019).

  - btrfs: make relocation use btrfs_read_tree_root()
    (bsc#1176019).

  - btrfs: make the fs root init functions static
    (bsc#1176019).

  - btrfs: make the init of static elements in fs_info
    separate (bsc#1176019).

  - btrfs: move all reflink implementation code into its own
    file (bsc#1176019).

  - btrfs: move block_group_item::flags to block group
    (bsc#1176019).

  - btrfs: move block_group_item::used to block group
    (bsc#1176019).

  - btrfs: move fs_info init work into it's own helper
    function (bsc#1176019).

  - btrfs: move fs root init stuff into btrfs_init_fs_root
    (bsc#1176019).

  - btrfs: open code btrfs_read_fs_root_no_name
    (bsc#1176019).

  - btrfs: push btrfs_grab_fs_root into btrfs_get_fs_root
    (bsc#1176019).

  - btrfs: push grab_fs_root into read_fs_root
    (bsc#1176019).

  - btrfs: push __setup_root into btrfs_alloc_root
    (bsc#1176019).

  - btrfs: reloc: clean dirty subvols if we fail to start a
    transaction (bsc#1176019).

  - btrfs: remove a BUG_ON() from merge_reloc_roots()
    (bsc#1176019).

  - btrfs: Remove block_rsv parameter from
    btrfs_drop_snapshot (bsc#1176019).

  - btrfs: remove btrfs_read_fs_root, not used anymore
    (bsc#1176019).

  - btrfs: remove embedded block_group_cache::item
    (bsc#1176019).

  - btrfs: Remove newest_gen argument from
    find_oldest_super_backup (bsc#1176019).

  - btrfs: Remove unused next_root_backup function
    (bsc#1176019).

  - btrfs: rename block_group_item on-stack accessors to
    follow naming (bsc#1176019).

  - btrfs: rename btrfs_block_group_cache (bsc#1176019).

  - btrfs: rename btrfs_put_fs_root and btrfs_grab_fs_root
    (bsc#1176019).

  - btrfs: rename extent buffer block group item accessors
    (bsc#1176019).

  - btrfs: Rename find_oldest_super_backup to
    init_backup_root_slot (bsc#1176019).

  - btrfs: require only sector size alignment for parent eb
    bytenr (bsc#1176789).

  - btrfs: reset tree root pointer after error in
    init_tree_roots (bsc#1176019).

  - btrfs: simplify inline extent handling when doing
    reflinks (bsc#1176019).

  - btrfs: stop clearing EXTENT_DIRTY in inode I/O tree
    (bsc#1176019).

  - btrfs: Streamline btrfs_fs_info::backup_root_index
    semantics (bsc#1176019).

  - btrfs: tree-checker: fix the error message for transid
    error (bsc#1176788).

  - btrfs: unset reloc control if we fail to recover
    (bsc#1176019).

  - btrfs: use bool argument in free_root_pointers()
    (bsc#1176019).

  - btrfs: use btrfs_block_group_cache_done in
    update_block_group (bsc#1176019).

  - btrfs: use btrfs_put_fs_root to free roots always
    (bsc#1176019).

  - ceph: do not allow setlease on cephfs (bsc#1176537).

  - ceph: fix potential mdsc use-after-free crash
    (bsc#1176538).

  - ceph: fix use-after-free for fsc->mdsc (bsc#1176539).

  - ceph: handle zero-length feature mask in session
    messages (bsc#1176540).

  - ceph: set sec_context xattr on symlink creation
    (bsc#1176541).

  - ceph: use frag's MDS in either mode (bsc#1176542).

  - cfg80211: regulatory: reject invalid hints
    (bsc#1176699).

  - char: virtio: Select VIRTIO from VIRTIO_CONSOLE
    (bsc#1175667).

  - cifs: Fix leak when handling lease break for cached root
    fid (bsc#1176242).

  - cifs/smb3: Fix data inconsistent when punch hole
    (bsc#1176544).

  - cifs/smb3: Fix data inconsistent when zero file range
    (bsc#1176536).

  - clk: davinci: Use the correct size when allocating
    memory (git-fixes).

  - clk: rockchip: Fix initialization of mux_pll_src_4plls_p
    (git-fixes).

  - cxgb4: fix thermal zone device registration (git-fixes).

  - dax: do not print error message for non-persistent
    memory block device (bsc#1171073).

  - dax: print error message by pr_info() in
    __generic_fsdax_supported() (bsc#1171073).

  - debugfs: Fix module state check condition (bsc#1173746).

  - debugfs: Fix module state check condition (git-fixes).

  - dev: Defer free of skbs in flush_backlog
    (networking-stable-20_07_29).

  - device property: Fix the secondary firmware node
    handling in set_primary_fwnode() (git-fixes).

  - dmaengine: acpi: Put the CSRT table after using it
    (git-fixes).

  - dmaengine: at_hdmac: check return value of
    of_find_device_by_node() in at_dma_xlate() (git-fixes).

  - dmaengine: dw-edma: Fix scatter-gather address
    calculation (git-fixes).

  - dmaengine: of-dma: Fix of_dma_router_xlate's
    of_dma_xlate handling (git-fixes).

  - dmaengine: pl330: Fix burst length if burst size is
    smaller than bus width (git-fixes).

  - dm: do not call report zones for more than the user
    requested (git fixes (block drivers)).

  - dm integrity: fix integrity recalculation that is
    improperly skipped (git fixes (block drivers)).

  - dm rq: do not call blk_mq_queue_stopped() in
    dm_stop_queue() (git fixes (block drivers)).

  - dm writecache: add cond_resched to loop in
    persistent_memory_claim() (git fixes (block drivers)).

  - dm writecache: correct uncommitted_block when discarding
    uncommitted entry (git fixes (block drivers)).

  - dm zoned: assign max_io_len correctly (git fixes (block
    drivers)).

  - dpaa2-eth: Fix passing zero to 'PTR_ERR' warning
    (networking-stable-20_08_08).

  - dpaa_eth: Fix one possible memleak in dpaa_eth_probe
    (bsc#1175996).

  - driver-core: Introduce DEVICE_ATTR_ADMIN_(RO,RW)
    (bsc#1176486 ltc#188130).

  - drivers: hv: Specify receive buffer size using Hyper-V
    page size (bsc#1176877).

  - drivers: hv: vmbus: Add timeout to vmbus_wait_for_unload
    (git-fixes).

  - drivers: hv: vmbus: hibernation: do not hang forever in
    vmbus_bus_resume() (git-fixes).

  - drivers/net/wan/x25_asy: Fix to make it work
    (networking-stable-20_07_29).

  - drm/amd/display: fix ref count leak in amdgpu_drm_ioctl
    (git-fixes).

  - drm/amd/display: Switch to immediate mode for updating
    infopackets (git-fixes).

  - drm/amdgpu/display: fix ref count leak when
    pm_runtime_get_sync fails (git-fixes).

  - drm/amdgpu: Fix buffer overflow in INFO ioctl
    (git-fixes).

  - drm/amdgpu: fix ref count leak in
    amdgpu_display_crtc_set_config (git-fixes).

  - drm/amdgpu: fix ref count leak in amdgpu_driver_open_kms
    (git-fixes).

  - drm/amdgpu/gfx10: refine mgcg setting (git-fixes).

  - drm/amdkfd: Fix reference count leaks (git-fixes).

  - drm/amd/pm: correct the thermal alert temperature limit
    settings (git-fixes).

  - drm/amd/pm: correct Vega10 swctf limit setting
    (git-fixes).

  - drm/amd/pm: correct Vega12 swctf limit setting
    (git-fixes).

  - drm/amd/pm: correct Vega20 swctf limit setting
    (git-fixes).

  - drm/amd/powerplay: correct UVD/VCE PG state on custom
    pptable uploading (git-fixes).

  - drm/amd/powerplay: correct Vega20 cached smu feature
    state (git-fixes).

  - drm/amd/powerplay: Fix hardmins not being sent to SMU
    for RV (git-fixes).

  - drm/ast: Initialize DRAM type before posting GPU
    (bsc#1152472)

  - drm/mgag200: Remove declaration of mgag200_mmap() from
    header file (bsc#1152472)

  - drm/msm/a6xx: fix crashdec section name typo
    (git-fixes).

  - drm/msm/adreno: fix updating ring fence (git-fixes).

  - drm/msm/gpu: make ringbuffer readonly (git-fixes).

  - drm/nouveau/drm/noveau: fix reference count leak in
    nouveau_fbcon_open (git-fixes).

  - drm/nouveau: Fix reference count leak in
    nouveau_connector_detect (git-fixes).

  - drm/nouveau: fix reference count leak in
    nv50_disp_atomic_commit (git-fixes).

  - drm/radeon: fix multiple reference count leak
    (git-fixes).

  - drm/radeon: Prefer lower feedback dividers (git-fixes).

  - drm/sched: Fix passing zero to 'PTR_ERR' warning v2
    (git-fixes).

  - drm/sun4i: add missing put_device() call in
    (bsc#1152472)

  - drm/sun4i: backend: Disable alpha on the lowest plane on
    the A20 (bsc#1152472)

  - drm/sun4i: backend: Support alpha property on lowest
    plane (bsc#1152472)

  - drm/sun4i: Fix dsi dcs long write function (bsc#1152472)

  - drm/virtio: fix missing dma_fence_put() in (bsc#1152489)

  - drm/xen-front: Fix misused IS_ERR_OR_NULL checks
    (bsc#1065600).

  - EDAC/amd64: Add AMD family 17h model 60h PCI IDs
    (bsc#1152489).

  - EDAC/amd64: Read back the scrub rate PCI register on
    F15h (bsc#1152489).

  - EDAC: Fix reference count leaks (bsc#1152489).

  - efi: Add support for EFI_RT_PROPERTIES table
    (bsc#1174029, bsc#1174110, bsc#1174111).

  - efi: avoid error message when booting under Xen
    (bsc#1172419).

  - efi/efivars: Expose RT service availability via efivars
    abstraction (bsc#1174029, bsc#1174110, bsc#1174111).

  - efi: libstub/tpm: enable tpm eventlog function for ARM
    platforms (bsc#1173267).

  - efi: Mark all EFI runtime services as unsupported on
    non-EFI boot (bsc#1174029, bsc#1174110, bsc#1174111).

  - efi: Register EFI rtc platform device only when
    available (bsc#1174029, bsc#1174110, bsc#1174111).

  - efi: Store mask of supported runtime services in struct
    efi (bsc#1174029, bsc#1174110, bsc#1174111).

  - efi: Use EFI ResetSystem only when available
    (bsc#1174029, bsc#1174110, bsc#1174111).

  - efi: Use more granular check for availability for
    variable services (bsc#1174029, bsc#1174110,
    bsc#1174111).

  - enetc: Remove the mdio bus on PF probe bailout
    (networking-stable-20_07_29).

  - epoll: atomically remove wait entry on wake up
    (bsc#1176236).

  - epoll: call final ep_events_available() check under the
    lock (bsc#1176237).

  - ext4: handle read only external journal device
    (bsc#1176063).

  - fbcon: prevent user font height or width change from
    causing potential out-of-bounds access (git-fixes).

  - fbmem: pull fbcon_update_vcs() out of fb_set_var()
    (git-fixes).

  - felix: Fix initialization of ioremap resources
    (bsc#1175997).

  - Fix build error when CONFIG_ACPI is not set/enabled:
    (bsc#1065600).

  - ftrace: Setup correct FTRACE_FL_REGS flags for module
    (git-fixes).

  - HID: core: Add printk_once variants to hid_warn() etc
    (bsc#1176775).

  - HID: core: Correctly handle ReportSize being zero
    (git-fixes).

  - HID: core: fix dmesg flooding if report field larger
    than 32bit (bsc#1176775).

  - HID: core: reformat and reduce hid_printk macros
    (bsc#1176775).

  - HID: core: Sanitize event code and type when mapping
    input (git-fixes).

  - HID: elan: Fix memleak in elan_input_configured
    (git-fixes).

  - HID: hiddev: Fix slab-out-of-bounds write in
    hiddev_ioctl_usage() (git-fixes).

  - HID: i2c-hid: Always sleep 60ms after I2C_HID_PWR_ON
    commands (git-fixes).

  - HID: microsoft: Add rumble support for the 8bitdo SN30
    Pro+ controller (git-fixes).

  - HID: quirks: add NOGET quirk for Logitech GROUP
    (git-fixes).

  - HID: quirks: Always poll three more Lenovo PixArt mice
    (git-fixes).

  - HID: quirks: Set INCREMENT_USAGE_ON_DUPLICATE for all
    Saitek X52 devices (git-fixes).

  - hsr: use netdev_err() instead of WARN_ONCE()
    (bsc#1176659).

  - hv_netvsc: do not use VF device if link is down
    (git-fixes).

  - hv_netvsc: Fix the queue_mapping in netvsc_vf_xmit()
    (git-fixes).

  - hv_netvsc: Remove 'unlikely' from netvsc_select_queue
    (git-fixes).

  - hv_utils: drain the timesync packets on
    onchannelcallback (bsc#1176877).

  - hv_utils: return error if host timesysnc update is stale
    (bsc#1176877).

  - i2c: algo: pca: Reapply i2c bus settings after reset
    (git-fixes).

  - i2c: core: Do not fail PRP0001 enumeration when no ID
    table exist (git-fixes).

  - i2c: i801: Fix resume bug (git-fixes).

  - i2c: mxs: use MXS_DMA_CTRL_WAIT4END instead of
    DMA_CTRL_ACK (git-fixes).

  - i2c: rcar: in slave mode, clear NACK earlier
    (git-fixes).

  - i40e: Fix crash during removing i40e driver (git-fixes).

  - i40e: Set RX_ONLY mode for unicast promiscuous on VLAN
    (git-fixes).

  - ibmvnic: add missing parenthesis in do_reset()
    (bsc#1176700 ltc#188140).

  - iio:accel:bmc150-accel: Fix timestamp alignment and
    prevent data leak (git-fixes).

  - iio: accel: kxsd9: Fix alignment of local buffer
    (git-fixes).

  - iio:accel:mma7455: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:accel:mma8452: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:adc:ina2xx Fix timestamp alignment issue
    (git-fixes).

  - iio:adc:max1118 Fix alignment of timestamp and data leak
    issues (git-fixes).

  - iio: adc: mcp3422: fix locking on error path
    (git-fixes).

  - iio: adc: mcp3422: fix locking scope (git-fixes).

  - iio:adc:ti-adc081c Fix alignment and data leak issues
    (git-fixes).

  - iio:adc:ti-adc084s021 Fix alignment and data leak issues
    (git-fixes).

  - iio: adc: ti-ads1015: fix conversion when CONFIG_PM is
    not set (git-fixes).

  - iio:chemical:ccs811: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio: dac: ad5592r: fix unbalanced mutex unlocks in
    ad5592r_read_raw() (git-fixes).

  - iio:light:ltr501 Fix timestamp alignment issue
    (git-fixes).

  - iio:light:max44000 Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:magnetometer:ak8975 Fix alignment and data leak
    issues (git-fixes).

  - iio:proximity:mb1232: Fix timestamp alignment and
    prevent data leak (git-fixes).

  - include/asm-generic/vmlinux.lds.h: align ro_after_init
    (git-fixes).

  - include/linux/bitops.h: avoid clang shift-count-overflow
    warnings (git-fixes).

  - include/linux/poison.h: remove obsolete comment
    (git-fixes).

  - infiniband: hfi1: Use EFI GetVariable only when
    available (bsc#1174029, bsc#1174110, bsc#1174111).

  - initramfs: remove clean_rootfs (git-fixes).

  - initramfs: remove the populate_initrd_image and
    clean_rootfs stubs (git-fixes).

  - Input: i8042 - add Entroware Proteus EL07R4 to nomux and
    reset lists (git-fixes).

  - Input: trackpoint - add new trackpoint variant IDs
    (git-fixes).

  - integrity: Check properly whether EFI GetVariable() is
    available (bsc#1174029, bsc#1174110, bsc#1174111).

  - iommu/amd: Do not force direct mapping when SME is
    active (bsc#1174358).

  - iommu/amd: Do not use IOMMUv2 functionality when SME is
    active (bsc#1174358).

  - iommu/amd: Print extended features in one line to fix
    divergent log levels (bsc#1176357).

  - iommu/amd: Restore IRTE.RemapEn bit after programming
    IRTE (bsc#1176358).

  - iommu/amd: Use cmpxchg_double() when updating 128-bit
    IRTE (bsc#1176359).

  - iommu/omap: Check for failure of a call to
    omap_iommu_dump_ctx (bsc#1176360).

  - iommu/vt-d: Fix PASID devTLB invalidation (bsc#1176361).

  - iommu/vt-d: Handle 36bit addressing for x86-32
    (bsc#1176362).

  - iommu/vt-d: Handle non-page aligned address
    (bsc#1176367).

  - iommu/vt-d: Remove global page support in devTLB flush
    (bsc#1176363).

  - iommu/vt-d: Serialize IOMMU GCMD register modifications
    (bsc#1176364).

  - iommu/vt-d: Support flushing more translation cache
    types (bsc#1176365).

  - ipv4: Silence suspicious RCU usage warning
    (networking-stable-20_08_08).

  - ipv6: fix memory leaks on IPV6_ADDRFORM path
    (networking-stable-20_08_08).

  - ipv6: Fix nexthop refcnt leak when creating ipv6 route
    info (networking-stable-20_08_08).

  - irqdomain/treewide: Free firmware node after domain
    removal (git-fixes).

  - irqdomain/treewide: Keep firmware node unconditionally
    allocated (git-fixes).

  - kABI: Fix kABI after EFI_RT_PROPERTIES table backport
    (bsc#1174029, bsc#1174110, bsc#1174111).

  - kABI: net: dsa: microchip: call phy_remove_link_mode
    during probe (kabi).

  - kabi/severities: ignore kABI for net/ethernet/mscc/
    References: bsc#1176001,bsc#1175999 Exported symbols
    from drivers/net/ethernet/mscc/ are only used by
    drivers/net/dsa/ocelot/

  - kernel/cpu_pm: Fix uninitted local in cpu_pm (git fixes
    (kernel/pm)).

  - kernel-syms.spec.in: Also use bz compression
    (boo#1175882).

  - libata: implement ATA_HORKAGE_MAX_TRIM_128M and apply to
    Sandisks (jsc#SLE-14459).

  - libbpf: Fix readelf output parsing for Fedora
    (bsc#1155518).

  - libbpf: Fix readelf output parsing on powerpc with
    recent binutils (bsc#1155518).

  - libnvdimm: cover up nvdimm_security_ops changes
    (bsc#1171742).

  - libnvdimm: cover up struct nvdimm changes (bsc#1171742).

  - libnvdimm/security: fix a typo (bsc#1171742
    bsc#1167527).

  - libnvdimm/security: Introduce a 'frozen' attribute
    (bsc#1171742).

  - livepatch: Add -fdump-ipa-clones to build (). Add
    support for -fdump-ipa-clones GCC option. Update config
    files accordingly.

  - md: raid0/linear: fix dereference before null check on
    pointer mddev (git fixes (block drivers)).

  - media: cedrus: Add missing v4l2_ctrl_request_hdl_put()
    (git-fixes).

  - media: davinci: vpif_capture: fix potential double free
    (git-fixes).

  - media: gpio-ir-tx: improve precision of transmitted
    signal due to scheduling (git-fixes).

  - media: pci: ttpci: av7110: fix possible buffer overflow
    caused by bad DMA value in debiirq() (git-fixes).

  - mei: fix CNL itouch device number to match the spec
    (bsc#1175952).

  - mei: me: disable mei interface on LBG servers
    (bsc#1175952).

  - mei: me: disable mei interface on Mehlow server
    platforms (bsc#1175952).

  - mfd: intel-lpss: Add Intel Emmitsburg PCH PCI IDs
    (git-fixes).

  - mlx4: disable device on shutdown (git-fixes).

  - mlxsw: destroy workqueue when trap_register in
    mlxsw_emad_init (networking-stable-20_07_29).

  - mmc: dt-bindings: Add resets/reset-names for Mediatek
    MMC bindings (git-fixes).

  - mmc: mediatek: add optional module reset property
    (git-fixes).

  - mmc: sdhci-acpi: Clear amd_sdhci_host on reset
    (git-fixes).

  - mmc: sdhci-acpi: Fix HS400 tuning for AMDI0040
    (git-fixes).

  - mmc: sdhci-msm: Add retries when all tuning phases are
    found valid (git-fixes).

  - mmc: sdhci-of-esdhc: Do not walk device-tree on every
    interrupt (git-fixes).

  - mmc: sdio: Use mmc_pre_req() / mmc_post_req()
    (git-fixes).

  - mm: limit boost_watermark on small zones (git fixes
    (mm/pgalloc)).

  - mm, page_alloc: fix core hung in free_pcppages_bulk()
    (git fixes (mm/pgalloc)).

  - mm/page_alloc: silence a KASAN false positive (git fixes
    (mm/pgalloc)).

  - mm: remove VM_BUG_ON(PageSlab()) from page_mapcount()
    (git fixes (mm/compaction)).

  - mm/shuffle: do not move pages between zones and do not
    read garbage memmaps (git fixes (mm/pgalloc)).

  - mm/sparse: rename pfn_present() to
    pfn_in_present_section() (git fixes (mm/pgalloc)).

  - mm, thp: fix defrag setting if newline is not used (git
    fixes (mm/thp)).

  - move to sorted section:
    patches.suse/x86-asm-64-Align-start-of-__clear_user-loop
    -to-16-by.patch

  - net: dp83640: fix SIOCSHWTSTAMP to update the struct
    with actual configuration (networking-stable-20_07_29).

  - net: dsa: felix: send VLANs on CPU port as egress-tagged
    (bsc#1175998).

  - net: dsa: microchip: call phy_remove_link_mode during
    probe (networking-stable-20_07_29).

  - net: dsa: ocelot: the MAC table on Felix is twice as
    large (bsc#1175999).

  - net: enetc: fix an issue about leak system resources
    (bsc#1176000).

  - net: ethernet: mlx4: Fix memory allocation in
    mlx4_buddy_init() (git-fixes).

  - net: ethernet: mtk_eth_soc: fix MTU warnings
    (networking-stable-20_08_08).

  - netfilter: ipset: Fix forceadd evaluation path
    (bsc#1176587).

  - net: Fix potential memory leak in proto_register()
    (networking-stable-20_08_15).

  - net: gre: recompute gre csum for sctp over gre tunnels
    (networking-stable-20_08_08).

  - net: initialize fastreuse on inet_inherit_port
    (networking-stable-20_08_15).

  - net: mscc: ocelot: fix untagged packet drops when
    enslaving to vlan aware bridge (bsc#1176001).

  - net/nfc/rawsock.c: add CAP_NET_RAW check
    (networking-stable-20_08_15).

  - net: refactor bind_bucket fastreuse into helper
    (networking-stable-20_08_15).

  - net: sched: initialize with 0 before setting erspan
    md->u (bsc#1154353).

  - net: Set fput_needed iff FDPUT_FPUT is set
    (networking-stable-20_08_15).

  - net/smc: put slot when connection is killed (git-fixes).

  - net-sysfs: add a newline when printing 'tx_timeout' by
    sysfs (networking-stable-20_07_29).

  - net: thunderx: use spin_lock_bh in
    nicvf_set_rx_mode_task() (networking-stable-20_08_08).

  - net/tls: Fix kmap usage (networking-stable-20_08_15).

  - net: udp: Fix wrong clean up for IS_UDPLITE macro
    (networking-stable-20_07_29).

  - NFC: st95hf: Fix memleak in st95hf_in_send_cmd
    (git-fixes).

  - nvme-fc: set max_segments to lldd max value
    (bsc#1176038).

  - nvme-pci: override the value of the controller's numa
    node (bsc#1176507).

  - obsolete_kmp: provide newer version than the obsoleted
    one (boo#1170232).

  - omapfb: fix multiple reference count leaks due to
    pm_runtime_get_sync (git-fixes).

  - openvswitch: Prevent kernel-infoleak in ovs_ct_put_key()
    (networking-stable-20_08_08).

  - PCI: Add device even if driver attach failed
    (git-fixes).

  - PCI: Avoid Pericom USB controller OHCI/EHCI PME# defect
    (git-fixes).

  - PCI: Fix pci_create_slot() reference count leak
    (git-fixes).

  - PCI: Mark AMD Navi10 GPU rev 0x00 ATS as broken
    (git-fixes).

  - platform/x86: dcdbas: Check SMBIOS for protected buffer
    address (jsc#SLE-14407).

  - PM: sleep: core: Fix the handling of pending runtime
    resume requests (git-fixes).

  - powerpc/64: mark emergency stacks valid to unwind
    (bsc#1156395).

  - powerpc/64s: machine check do not trace real-mode
    handler (bsc#1094244 ltc#168122).

  - powerpc/64s: machine check interrupt update NMI
    accounting (bsc#1094244 ltc#168122).

  - powerpc: Add cputime_to_nsecs() (bsc#1065729).

  - powerpc/book3s64/radix: Add kernel command line option
    to disable radix GTSE (bsc#1055186 ltc#153436
    jsc#SLE-13512).

  - powerpc/book3s64/radix: Fix boot failure with large
    amount of guest memory (bsc#1176022 ltc#187208).

  - powerpc: Do not flush caches when adding memory
    (bsc#1176980 ltc#187962).

  - powerpc: Implement ftrace_enabled() helpers (bsc#1094244
    ltc#168122).

  - powerpc/kernel: Cleanup machine check function
    declarations (bsc#1065729).

  - powerpc/kernel: Enables memory hot-remove after reboot
    on pseries guests (bsc#1177030 ltc#187588).

  - powerpc/mm: Enable radix GTSE only if supported
    (bsc#1055186 ltc#153436 jsc#SLE-13512).

  - powerpc/mm: Limit resize_hpt_for_hotplug() call to hash
    guests only (bsc#1177030 ltc#187588).

  - powerpc/mm/radix: Create separate mappings for
    hot-plugged memory (bsc#1055186 ltc#153436).

  - powerpc/mm/radix: Fix PTE/PMD fragment count for early
    page table mappings (bsc#1055186 ltc#153436).

  - powerpc/mm/radix: Free PUD table when freeing pagetable
    (bsc#1055186 ltc#153436).

  - powerpc/mm/radix: Remove split_kernel_mapping()
    (bsc#1055186 ltc#153436).

  - powerpc/numa: Early request for home node associativity
    (bsc#1171068 ltc#183935).

  - powerpc/numa: Offline memoryless cpuless node 0
    (bsc#1171068 ltc#183935).

  - powerpc/numa: Prefer node id queried from vphn
    (bsc#1171068 ltc#183935).

  - powerpc/numa: Set numa_node for all possible cpus
    (bsc#1171068 ltc#183935).

  - powerpc/numa: Use cpu node map of first sibling thread
    (bsc#1171068 ltc#183935).

  - powerpc/papr_scm: Limit the readability of 'perf_stats'
    sysfs attribute (bsc#1176486 ltc#188130).

  - powerpc/perf: Fix crashes with generic_compat_pmu & BHRB
    (bsc#1156395).

  - powerpc/prom: Enable Radix GTSE in cpu pa-features
    (bsc#1055186 ltc#153436 jsc#SLE-13512).

  - powerpc/pseries: Limit machine check stack to 4GB
    (bsc#1094244 ltc#168122).

  - powerpc/pseries: Machine check use rtas_call_unlocked()
    with args on stack (bsc#1094244 ltc#168122).

  - powerpc/pseries/ras: Avoid calling rtas_token() in NMI
    paths (bsc#1094244 ltc#168122).

  - powerpc/pseries/ras: Fix FWNMI_VALID off by one
    (bsc#1094244 ltc#168122).

  - powerpc/pseries/ras: fwnmi avoid modifying r3 in error
    case (bsc#1094244 ltc#168122).

  - powerpc/pseries/ras: fwnmi sreset should not interlock
    (bsc#1094244 ltc#168122).

  - powerpc/traps: Do not trace system reset (bsc#1094244
    ltc#168122).

  - powerpc/traps: Make unrecoverable NMIs die instead of
    panic (bsc#1094244 ltc#168122).

  - powerpc/xmon: Use `dcbf` inplace of `dcbi` instruction
    for 64bit Book3S (bsc#1065729).

  - qrtr: orphan socket in qrtr_release()
    (networking-stable-20_07_29).

  - RDMA/bnxt_re: Do not report transparent vlan from QP1
    (bsc#1173017).

  - RDMA/bnxt_re: Fix the qp table indexing (bsc#1173017).

  - RDMA/bnxt_re: Remove set but not used variable
    'qplib_ctx' (bsc#1170774).

  - RDMA/bnxt_re: Remove the qp from list only if the qp
    destroy succeeds (bsc#1170774).

  - RDMA/bnxt_re: Restrict the max_gids to 256
    (bsc#1173017).

  - RDMA/bnxt_re: Static NQ depth allocation (bsc#1170774).

  - RDMA/mlx4: Read pkey table length instead of hardcoded
    value (git-fixes).

  - RDMA/siw: Suppress uninitialized var warning
    (jsc#SLE-8381).

  - regulator: core: Fix slab-out-of-bounds in
    regulator_unlock_recursive() (git-fixes).

  - regulator: fix memory leak on error path of
    regulator_register() (git-fixes).

  - regulator: plug of_node leak in regulator_register()'s
    error path (git-fixes).

  - regulator: push allocation in
    regulator_ena_gpio_request() out of lock (git-fixes).

  - regulator: push allocation in regulator_init_coupling()
    outside of lock (git-fixes).

  - regulator: push allocation in
    set_consumer_device_supply() out of lock (git-fixes).

  - regulator: push allocations in create_regulator()
    outside of lock (git-fixes).

  - regulator: pwm: Fix machine constraints application
    (git-fixes).

  - regulator: remove superfluous lock in
    regulator_resolve_coupling() (git-fixes).

  - Remove patch causing regression (bsc#1094244
    ltc#168122).

  - Revert 'ALSA: hda: Add support for Loongson 7A1000
    controller' (git-fixes).

  - Revert 'ALSA: hda - Fix silent audio output and
    corrupted input on MSI X570-A PRO' (git-fixes).

  - Revert 'ALSA: usb-audio: Disable Lenovo P620 Rear
    line-in volume control' (git-fixes).

  - Revert 'crypto: chelsio - Inline single pdu only'
    (git-fixes).

  - Revert 'xen/balloon: Fix crash when ballooning on x86 32
    bit PAE' (bsc#1065600).

  - rpadlpar_io: Add MODULE_DESCRIPTION entries to kernel
    modules (bsc#1176869 ltc#188243).

  - rpm/constraints.in: recognize also kernel-source-azure
    (bsc#1176732)

  - rpm/kernel-binary.spec.in: Also sign ppc64 kernels
    (jsc#SLE-15857 jsc#SLE-13618).

  - rpm/kernel-source.spec.in: Also use bz compression
    (boo#1175882).

  - rpm/macros.kernel-source: pass -c proerly in kernel
    module package (bsc#1176698) The '-c' option wasn't
    passed down to %_kernel_module_package so the ueficert
    subpackage wasn't generated even if the certificate is
    specified in the spec file.

  - rtlwifi: rtl8192cu: Prevent leaking urb (git-fixes).

  - rxrpc: Fix race between recvmsg and sendmsg on immediate
    call failure (networking-stable-20_08_08).

  - rxrpc: Fix sendmsg() returning EPIPE due to recvmsg()
    returning ENODATA (networking-stable-20_07_29).

  - s390: Change s390_kernel_write() return type to match
    memcpy() (bsc#1176449). Prerequisite for bsc#1176449.

  - s390/dasd: fix inability to use DASD with DIAG driver
    (git-fixes).

  - s390: fix GENERIC_LOCKBREAK dependency typo in Kconfig
    (git-fixes).

  - s390/maccess: add no DAT mode to kernel_write
    (bsc#1176449).

  - s390/mm: fix huge pte soft dirty copying (git-fixes).

  - s390/qeth: do not process empty bridge port events
    (git-fixes).

  - s390/qeth: integrate RX refill worker with NAPI
    (git-fixes).

  - s390/qeth: tolerate pre-filled RX buffer (git-fixes).

  - s390/setup: init jump labels before command line parsing
    (git-fixes).

  - sbitmap: Consider cleared bits in sbitmap_bitmap_show()
    (git fixes (block drivers)).

  - sched: Add a tracepoint to track rq->nr_running
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched: Better document ttwu() (bnc#1155798 (CPU
    scheduler functional and performance backports)).

  - sched/cputime: Improve cputime_adjust() (bnc#1155798
    (CPU scheduler functional and performance backports)).

  - sched/debug: Add new tracepoints to track util_est
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched/debug: Fix the alignment of the show-state debug
    output (bnc#1155798 (CPU scheduler functional and
    performance backports)).

  - sched/fair: fix NOHZ next idle balance (bnc#1155798 (CPU
    scheduler functional and performance backports)).

  - sched/fair: Remove unused 'sd' parameter from
    scale_rt_capacity() (bnc#1155798 (CPU scheduler
    functional and performance backports)).

  - sched/fair: update_pick_idlest() Select group with
    lowest group_util when idle_cpus are equal (bnc#1155798
    (CPU scheduler functional and performance backports)).

  - sched: Fix use of count for nr_running tracepoint
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched: nohz: stop passing around unused 'ticks'
    parameter (bnc#1155798 (CPU scheduler functional and
    performance backports)).

  - sched/pelt: Remove redundant cap_scale() definition
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - scsi: fcoe: Memory leak fix in fcoe_sysfs_fcf_del()
    (bsc#1174899).

  - scsi: ibmvfc: Avoid link down on FS9100 canister reboot
    (bsc#1176962 ltc#188304).

  - scsi: ibmvfc: Use compiler attribute defines instead of
    __attribute__() (bsc#1176962 ltc#188304).

  - scsi: iscsi: Use EFI GetVariable only when available
    (bsc#1174029, bsc#1174110, bsc#1174111).

  - scsi: libfc: Fix for double free() (bsc#1174899).

  - scsi: libfc: Free skb in fc_disc_gpn_id_resp() for valid
    cases (bsc#1174899).

  - scsi: lpfc: Add and rename a whole bunch of function
    parameter descriptions (bsc#1171558 bsc#1136666
    bsc#1174486 bsc#1175787 bsc#1171000 jsc#SLE-15796
    jsc#SLE-15449).

  - scsi: lpfc: Add dependency on CPU_FREQ (git-fixes).

  - scsi: lpfc: Add description for lpfc_release_rpi()'s
    'ndlpl param (bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Add missing misc_deregister() for
    lpfc_init() (bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Avoid another null dereference in
    lpfc_sli4_hba_unset() (bsc#1171558 bsc#1136666
    bsc#1174486 bsc#1175787 bsc#1171000 jsc#SLE-15796
    jsc#SLE-15449).

  - scsi: lpfc: Correct some pretty obvious misdocumentation
    (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Ensure variable has the same stipulations as
    code using it (bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix a bunch of kerneldoc misdemeanors
    (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix FCoE speed reporting (bsc#1171558
    bsc#1136666 bsc#1174486 bsc#1175787 bsc#1171000
    jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix kerneldoc parameter
    formatting/misnaming/missing issues (bsc#1171558
    bsc#1136666 bsc#1174486 bsc#1175787 bsc#1171000
    jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix LUN loss after cable pull (bsc#1171558
    bsc#1136666 bsc#1174486 bsc#1175787 bsc#1171000
    jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix no message shown for lpfc_hdw_queue out
    of range value (bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix oops when unloading driver while running
    mds diags (bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix retry of PRLI when status indicates its
    unsupported (bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix RSCN timeout due to incorrect gidft
    counter (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix setting IRQ affinity with an empty CPU
    mask (git-fixes).

  - scsi: lpfc: Fix some function parameter descriptions
    (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix typo in comment for ULP (bsc#1171558
    bsc#1136666 bsc#1174486 bsc#1175787 bsc#1171000
    jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix-up around 120 documentation issues
    (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix-up formatting/docrot where appropriate
    (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Fix validation of bsg reply lengths
    (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: NVMe remote port devloss_tmo from lldd
    (bcs#1173060 bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).
    Replace
    patches.suse/lpfc-synchronize-nvme-transport-and-lpfc-dr
    iver-devloss_tmo.patch with upstream version of the fix.

  - scsi: lpfc: nvmet: Avoid hang / use-after-free again
    when destroying targetport (bsc#1171558 bsc#1136666
    bsc#1174486 bsc#1175787 bsc#1171000 jsc#SLE-15796
    jsc#SLE-15449).

  - scsi: lpfc: Provide description for lpfc_mem_alloc()'s
    'align' param (bsc#1171558 bsc#1136666 bsc#1174486
    bsc#1175787 bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Quieten some printks (bsc#1171558
    bsc#1136666 bsc#1174486 bsc#1175787 bsc#1171000
    jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Remove unused variable 'pg_addr'
    (bsc#1171558 bsc#1136666 bsc#1174486 bsc#1175787
    bsc#1171000 jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Update lpfc version to 12.8.0.3 (bsc#1171558
    bsc#1136666 bsc#1174486 bsc#1175787 bsc#1171000
    jsc#SLE-15796 jsc#SLE-15449).

  - scsi: lpfc: Use __printf() format notation (bsc#1171558
    bsc#1136666 bsc#1174486 bsc#1175787 bsc#1171000
    jsc#SLE-15796 jsc#SLE-15449).

  - scsi: qla2xxx: Fix regression on sparc64 (git-fixes).

  - scsi: qla2xxx: Fix the return value (bsc#1171688).

  - scsi: qla2xxx: Fix the size used in a
    'dma_free_coherent()' call (bsc#1171688).

  - scsi: qla2xxx: Fix wrong return value in
    qla_nvme_register_hba() (bsc#1171688).

  - scsi: qla2xxx: Fix wrong return value in
    qlt_chk_unresolv_exchg() (bsc#1171688).

  - scsi: qla2xxx: Handle incorrect entry_type entries
    (bsc#1171688).

  - scsi: qla2xxx: Log calling function name in
    qla2x00_get_sp_from_handle() (bsc#1171688).

  - scsi: qla2xxx: Remove pci-dma-compat wrapper API
    (bsc#1171688).

  - scsi: qla2xxx: Remove redundant variable initialization
    (bsc#1171688).

  - scsi: qla2xxx: Remove superfluous memset()
    (bsc#1171688).

  - scsi: qla2xxx: Simplify return value logic in
    qla2x00_get_sp_from_handle() (bsc#1171688).

  - scsi: qla2xxx: Suppress two recently introduced compiler
    warnings (git-fixes).

  - scsi: qla2xxx: Warn if done() or free() are called on an
    already freed srb (bsc#1171688).

  - scsi: zfcp: Fix use-after-free in request timeout
    handlers (git-fixes).

  - sctp: shrink stream outq only when new outcnt < old
    outcnt (networking-stable-20_07_29).

  - sctp: shrink stream outq when fails to do addstream
    reconf (networking-stable-20_07_29).

  - sdhci: tegra: Add missing TMCLK for data timeout
    (git-fixes).

  - sdhci: tegra: Remove SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK
    for Tegra186 (git-fixes).

  - sdhci: tegra: Remove SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK
    for Tegra210 (git-fixes).

  - selftests/net: relax cpu affinity requirement in
    msg_zerocopy test (networking-stable-20_08_08).

  - serial: 8250_pci: Add Realtek 816a and 816b (git-fixes).

  - Set VIRTIO_CONSOLE=y (bsc#1175667).

  - SMB3: Honor 'handletimeout' flag for multiuser mounts
    (bsc#1176558).

  - SMB3: Honor persistent/resilient handle flags for
    multiuser mounts (bsc#1176546).

  - SMB3: Honor 'posix' flag for multiuser mounts
    (bsc#1176559).

  - SMB3: Honor 'seal' flag for multiuser mounts
    (bsc#1176545).

  - smb3: warn on confusing error scenario with sec=krb5
    (bsc#1176548).

  - soundwire: fix double free of dangling pointer
    (git-fixes).

  - spi: Fix memory leak on splited transfers (git-fixes).

  - spi: spi-loopback-test: Fix out-of-bounds read
    (git-fixes).

  - spi: stm32: always perform registers configuration prior
    to transfer (git-fixes).

  - spi: stm32: clear only asserted irq flags on interrupt
    (git-fixes).

  - spi: stm32: fix fifo threshold level in case of short
    transfer (git-fixes).

  - spi: stm32: fix pm_runtime_get_sync() error checking
    (git-fixes).

  - spi: stm32: fix stm32_spi_prepare_mbr in case of odd
    clk_rate (git-fixes).

  - spi: stm32h7: fix race condition at end of transfer
    (git-fixes).

  - taprio: Fix using wrong queues in gate mask
    (bsc#1154353).

  - tcp: apply a floor of 1 for RTT samples from TCP
    timestamps (networking-stable-20_08_08).

  - tcp: correct read of TFO keys on big endian systems
    (networking-stable-20_08_15).

  - test_kmod: avoid potential double free in
    trigger_config_run_type() (git-fixes).

  - tg3: Fix soft lockup when tg3_reset_task() fails
    (git-fixes).

  - thermal: qcom-spmi-temp-alarm: Do not suppress negative
    temp (git-fixes).

  - thermal: ti-soc-thermal: Fix bogus thermal shutdowns for
    omap4430 (git-fixes).

  - tracing: fix double free (git-fixes).

  - Update
    patches.suse/btrfs-add-dedicated-members-for-start-and-l
    ength-of-.patch (bsc#1176019).

  - Update
    patches.suse/btrfs-Move-free_pages_out-label-in-inline-e
    xtent-han.patch (bsc#1174484).

  - update to September 2020 maintenance update submission
    (commit 8bb516dc7a0a)

  - USB: cdc-acm: rework notification_buffer resizing
    (git-fixes).

  - usb: core: fix slab-out-of-bounds Read in
    read_descriptors (git-fixes).

  - usb: Fix out of sync data toggle if a configured device
    is reconfigured (git-fixes).

  - USB: gadget: f_ncm: add bounds checks to
    ncm_unwrap_ntb() (git-fixes).

  - usb: gadget: f_tcm: Fix some resource leaks in some
    error paths (git-fixes).

  - USB: gadget: u_f: add overflow checks to VLA macros
    (git-fixes).

  - USB: gadget: u_f: Unbreak offset calculation in VLAs
    (git-fixes).

  - usb: host: ohci-exynos: Fix error handling in
    exynos_ohci_probe() (git-fixes).

  - usb: host: xhci: fix ep context print mismatch in
    debugfs (git-fixes).

  - USB: Ignore UAS for JMicron JMS567 ATA/ATAPI Bridge
    (git-fixes).

  - USB: lvtest: return proper error code in probe
    (git-fixes).

  - USB: quirks: Add no-lpm quirk for another Raydium
    touchscreen (git-fixes).

  - USB: quirks: Add USB_QUIRK_IGNORE_REMOTE_WAKEUP quirk
    for BYD zhaoxin notebook (git-fixes).

  - USB: quirks: Ignore duplicate endpoint on Sound Devices
    MixPre-D (git-fixes).

  - USB: rename USB quirk to USB_QUIRK_ENDPOINT_IGNORE
    (git-fixes).

  - USB: serial: ftdi_sio: add IDs for Xsens Mti USB
    converter (git-fixes).

  - USB: serial: ftdi_sio: clean up receive processing
    (git-fixes).

  - USB: serial: ftdi_sio: fix break and sysrq handling
    (git-fixes).

  - USB: serial: ftdi_sio: make process-packet buffer
    unsigned (git-fixes).

  - USB: serial: option: add support for
    SIM7070/SIM7080/SIM7090 modules (git-fixes).

  - USB: serial: option: support dynamic Quectel USB
    compositions (git-fixes).

  - USB: sisusbvga: Fix a potential UB casued by left
    shifting a negative value (git-fixes).

  - usb: storage: Add unusual_uas entry for Sony PSZ drives
    (git-fixes).

  - usb: typec: ucsi: acpi: Check the _DEP dependencies
    (git-fixes).

  - usb: typec: ucsi: Prevent mode overrun (git-fixes).

  - usb: uas: Add quirk for PNY Pro Elite (git-fixes).

  - USB: UAS: fix disconnect by unplugging a hub
    (git-fixes).

  - USB: yurex: Fix bad gfp argument (git-fixes).

  - vfio-pci: Avoid recursive read-lock usage (bsc#1176366).

  - virtio-blk: free vblk-vqs in error path of
    virtblk_probe() (git fixes (block drivers)).

  - virtio_pci_modern: Fix the comment of
    virtio_pci_find_capability() (git-fixes).

  - vsock/virtio: annotate 'the_virtio_vsock' RCU pointer
    (networking-stable-20_07_29).

  - vt: defer kfree() of vc_screenbuf in vc_do_resize()
    (git-fixes).

  - vxlan: Ensure FDB dump is performed under RCU
    (networking-stable-20_08_08).

  - wireguard: noise: take lock when removing handshake
    entry from table (git-fixes).

  - wireguard: peerlookup: take lock before checking hash in
    replace operation (git-fixes).

  - workqueue: require CPU hotplug read exclusion for
    apply_workqueue_attrs (bsc#1176763).

  - x86/hotplug: Silence APIC only after all interrupts are
    migrated (git-fixes).

  - x86/ima: Use EFI GetVariable only when available
    (bsc#1174029, bsc#1174110, bsc#1174111).

  - x86/mce/inject: Fix a wrong assignment of i_mce.status
    (bsc#1152489).

  - x86, sched: Bail out of frequency invariance if
    turbo_freq/base_freq gives 0 (bsc#1176925).

  - x86, sched: Bail out of frequency invariance if turbo
    frequency is unknown (bsc#1176925).

  - x86, sched: check for counters overflow in frequency
    invariant accounting (bsc#1176925).

  - x86/stacktrace: Fix reliable check for empty user task
    stacks (bsc#1058115).

  - x86/unwind/orc: Fix ORC for newly forked tasks
    (bsc#1058115).

  - xen/balloon: fix accounting in alloc_xenballooned_pages
    error path (bsc#1065600).

  - xen/balloon: make the balloon wait interruptible
    (bsc#1065600).

  - xen: do not reschedule in preemption off sections
    (bsc#1175749).

  - xen/gntdev: Fix dmabuf import with non-zero sgt offset
    (bsc#1065600).

  - XEN uses irqdesc::irq_data_common::handler_data to store
    a per interrupt XEN data pointer which contains XEN
    specific information (bsc#1065600).

  - xhci: Always restore EP_SOFT_CLEAR_TOGGLE even if ep
    reset failed (git-fixes).

  - xhci: Do warm-reset when both CAS and XDEV_RESUME are
    set (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177030"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14390");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.44.1.lp152.8.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.44.1.lp152.8.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.44.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.44.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-debuginfo / kernel-debug-debugsource / etc");
}
