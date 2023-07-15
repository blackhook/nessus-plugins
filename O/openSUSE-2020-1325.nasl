#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1325.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140365);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_cve_id("CVE-2018-3639", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-1749", "CVE-2020-24394");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1325) (Spectre)");
  script_summary(english:"Check for the openSUSE-2020-1325 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2018-3639: Systems with microprocessors utilizing
    speculative execution and speculative execution of
    memory reads before the addresses of all prior memory
    writes are known may have allowed unauthorized
    disclosure of information to an attacker with local user
    access via a side-channel analysis, aka Speculative
    Store Bypass (SSB), Variant 4 (bnc#1085308 bnc#1087082
    bnc#1172782 bnc#1172783). Mitigations for Arm had not
    been included yet.

  - CVE-2020-14314: Fixed potential negative array index in
    do_split() (bsc#1173798).

  - CVE-2020-14331: Fixed a buffer over write in
    vgacon_scroll (bnc#1174205).

  - CVE-2020-14356: A flaw NULL pointer dereference in the
    Linux kernel cgroupv2 subsystem in versions was found in
    the way when reboot the system. A local user could use
    this flaw to crash the system or escalate their
    privileges on the system (bnc#1175213).

  - CVE-2020-1749: Some ipv6 protocols were not encrypted
    over ipsec tunnels (bsc#1165629).

  - CVE-2020-24394: fs/nfsd/vfs.c (in the NFS server) could
    set incorrect permissions on new filesystem objects when
    the filesystem lacks ACL support, aka CID-22cf8419f131.
    This occurs because the current umask is not considered
    (bnc#1175518).

The following non-security bugs were fixed :

  - ACPI: kABI fixes for subsys exports (bsc#1174968).

  - ACPI / LPSS: Resume BYT/CHT I2C controllers from
    resume_noirq (bsc#1174968).

  - ACPI / LPSS: Use acpi_lpss_* instead of acpi_subsys_*
    functions for hibernate (bsc#1174968).

  - ACPI: PM: Introduce 'poweroff' callbacks for ACPI PM
    domain and LPSS (bsc#1174968).

  - ACPI: PM: Simplify and fix PM domain hibernation
    callbacks (bsc#1174968).

  - af_key: pfkey_dump needs parameter validation
    (git-fixes).

  - agp/intel: Fix a memory leak on module initialisation
    failure (git-fixes).

  - ALSA: core: pcm_iec958: fix kernel-doc (bsc#1111666).

  - ALSA: echoaduio: Drop superfluous volatile modifier
    (bsc#1111666).

  - ALSA: echoaudio: Fix potential Oops in snd_echo_resume()
    (bsc#1111666).

  - ALSA: hda: Add support for Loongson 7A1000 controller
    (bsc#1111666).

  - ALSA: hda/ca0132 - Add new quirk ID for Recon3D
    (bsc#1111666).

  - ALSA: hda/ca0132 - Fix AE-5 microphone selection
    commands (bsc#1111666).

  - ALSA: hda/ca0132 - Fix ZxR Headphone gain control get
    value (bsc#1111666).

  - ALSA: hda: fix snd_hda_codec_cleanup() documentation
    (bsc#1111666).

  - ALSA: hda - fix the micmute led status for Lenovo
    ThinkCentre AIO (bsc#1111666).

  - ALSA: hda/realtek: Add alc269/alc662 pin-tables for
    Loongson-3 laptops (bsc#1111666).

  - ALSA: hda/realtek: Add model alc298-samsung-headphone
    (git-fixes).

  - ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion
    (git-fixes).

  - ALSA: hda/realtek: Add quirk for Samsung Galaxy Flex
    Book (git-fixes).

  - ALSA: hda/realtek: Fix pin default on Intel NUC 8 Rugged
    (bsc#1111666).

  - ALSA: hda/realtek - Fix unused variable warning
    (bsc#1111666).

  - ALSA: hda - reverse the setting value in the
    micmute_led_set (bsc#1111666).

  - ALSA: pci: delete repeated words in comments
    (bsc#1111666).

  - ALSA: seq: oss: Serialize ioctls (bsc#1111666).

  - ALSA: usb-audio: Add capture support for Saffire 6 (USB
    1.1) (git-fixes).

  - ALSA: usb-audio: add quirk for Pioneer DDJ-RB
    (bsc#1111666).

  - ALSA: usb-audio: add startech usb audio dock name
    (bsc#1111666).

  - ALSA: usb-audio: Add support for Lenovo ThinkStation
    P620 (bsc#1111666).

  - ALSA: usb-audio: Creative USB X-Fi Pro SB1095 volume
    knob support (bsc#1111666).

  - ALSA: usb-audio: Disable Lenovo P620 Rear line-in volume
    control (bsc#1111666).

  - ALSA: usb-audio: endpoint : remove needless check before
    usb_free_coherent() (bsc#1111666).

  - ALSA: usb-audio: fix overeager device match for
    MacroSilicon MS2109 (bsc#1174625).

  - ALSA: usb-audio: fix spelling mistake 'buss' -> 'bus'
    (bsc#1111666).

  - ALSA: usb-audio: ignore broken processing/extension unit
    (git-fixes).

  - ALSA: usb-audio: Update documentation comment for MS2109
    quirk (git-fixes).

  - ALSA: usb-audio: work around streaming quirk for
    MacroSilicon MS2109 (bsc#1111666).

  - ALSA: usb/line6: remove 'defined but not used' warning
    (bsc#1111666).

  - arm64: Add MIDR encoding for HiSilicon Taishan CPUs
    (bsc#1174547).

  - arm64: Add MIDR encoding for NVIDIA CPUs (bsc#1174547).

  - arm64: add sysfs vulnerability show for meltdown
    (bsc#1174547).

  - arm64: Add sysfs vulnerability show for spectre-v1
    (bsc#1174547).

  - arm64: add sysfs vulnerability show for spectre-v2
    (bsc#1174547).

  - arm64: add sysfs vulnerability show for speculative
    store bypass (bsc#1174547).

  - arm64: Advertise mitigation of Spectre-v2, or lack
    thereof (bsc#1174547)

  - arm64: Always enable spectre-v2 vulnerability detection
    (bsc#1174547).

  - arm64: Always enable ssb vulnerability detection
    (bsc#1174547).

  - arm64: backtrace: Do not bother trying to unwind the
    userspace stack (bsc#1175397).

  - arm64: capabilities: Add NVIDIA Denver CPU to bp_harden
    list (bsc#1174547).

  - arm64: capabilities: Merge duplicate Cavium erratum
    entries (bsc#1174547).

  - arm64: capabilities: Merge entries for
    ARM64_WORKAROUND_CLEAN_CACHE (bsc#1174547).

  - arm64: cpufeature: Enable Qualcomm Falkor/Kryo errata
    1003 (bsc#1175398).

  - arm64: Do not mask out PTE_RDONLY in pte_same()
    (bsc#1175393).

  - arm64: enable generic CPU vulnerabilites support
    (bsc#1174547). Update config/arm64/default

  - arm64: Ensure VM_WRITE|VM_SHARED ptes are clean by
    default (bsc#1175394).

  - arm64: errata: Do not define type field twice for
    arm64_errata entries (bsc#1174547).

  - arm64: errata: Update stale comment (bsc#1174547).

  - arm64: Get rid of __smccc_workaround_1_hvc_*
    (bsc#1174547).

  - arm64: kpti: Avoid rewriting early page tables when
    KASLR is enabled (bsc#1174547).

  - arm64: kpti: Update arm64_kernel_use_ng_mappings() when
    forced on (bsc#1174547).

  - arm64: kpti: Whitelist Cortex-A CPUs that do not
    implement the CSV3 field (bsc#1174547).

  - arm64: kpti: Whitelist HiSilicon Taishan v110 CPUs
    (bsc#1174547).

  - arm64: KVM: Avoid setting the upper 32 bits of VTCR_EL2
    to 1 (bsc#1133021).

  - arm64: KVM: Guests can skip __install_bp_hardening_cb()s
    HYP work (bsc#1174547).

  - arm64: KVM: Use SMCCC_ARCH_WORKAROUND_1 for Falkor BP
    hardening (bsc#1174547).

  - arm64: mm: Fix pte_mkclean, pte_mkdirty semantics
    (bsc#1175526).

  - arm64: Provide a command line to disable spectre_v2
    mitigation (bsc#1174547).

  - arm64: Silence clang warning on mismatched
    value/register sizes (bsc#1175396).

  - arm64/speculation: Support 'mitigations=' cmdline option
    (bsc#1174547).

  - arm64: ssbd: explicitly depend on <linux/prctl.h>
    (bsc#1175399).

  - arm64: ssbs: Do not treat CPUs with SSBS as unaffected
    by SSB (bsc#1174547).

  - arm64: ssbs: Fix context-switch when SSBS is present on
    all CPUs (bsc#1175669).

  - arm64/sve: <uapi/asm/ptrace.h> should not depend on
    <uapi/linux/prctl.h> (bsc#1175401).

  - arm64/sve: Fix wrong free for task->thread.sve_state
    (bsc#1175400).

  - arm64: tlbflush: avoid writing RES0 bits (bsc#1175402).

  - arm64: Use firmware to detect CPUs that are not affected
    by Spectre-v2 (bsc#1174547).

  - ARM: KVM: invalidate BTB on guest exit for
    Cortex-A12/A17 (bsc#1133021).

  - ARM: KVM: invalidate icache on guest exit for Cortex-A15
    (bsc#1133021).

  - ARM: spectre-v2: KVM: invalidate icache on guest exit
    for Brahma B15 (bsc#1133021).

  - ASoC: hda/tegra: Set buffer alignment to 128 bytes
    (bsc#1111666).

  - ASoC: intel: Fix memleak in sst_media_open (git-fixes).

  - ASoC: rt5670: Correct RT5670_LDO_SEL_MASK (git-fixes).

  - AX.25: Fix out-of-bounds read in ax25_connect()
    (git-fixes).

  - AX.25: Prevent integer overflows in connect and sendmsg
    (git-fixes).

  - AX.25: Prevent out-of-bounds read in ax25_sendmsg()
    (git-fixes).

  - ax88172a: fix ax88172a_unbind() failures (git-fixes).

  - b43: Remove uninitialized_var() usage (git-fixes).

  - bcache: allocate meta data pages as compound pages
    (bsc#1172873).

  - block: check queue's limits.discard_granularity in
    __blkdev_issue_discard() (bsc#1152148).

  - block: improve discard bio alignment in
    __blkdev_issue_discard() (bsc#1152148).

  - Bluetooth: Fix slab-out-of-bounds read in
    hci_extended_inquiry_result_evt() (bsc#1111666).

  - Bluetooth: Fix update of connection state in
    `hci_encrypt_cfm` (git-fixes).

  - Bluetooth: Prevent out-of-bounds read in
    hci_inquiry_result_evt() (bsc#1111666).

  - Bluetooth: Prevent out-of-bounds read in
    hci_inquiry_result_with_rssi_evt() (bsc#1111666).

  - bonding: fix active-backup failover for current ARP
    slave (bsc#1174771).

  - bonding: fix a potential double-unregister (git-fixes).

  - bonding: show saner speed for broadcast mode
    (git-fixes).

  - bpf: Fix map leak in HASH_OF_MAPS map (git-fixes).

  - brcmfmac: keep SDIO watchdog running when
    console_interval is non-zero (bsc#1111666).

  - brcmfmac: set state of hanger slot to FREE when flushing
    PSQ (bsc#1111666).

  - brcmfmac: To fix Bss Info flag definition Bug
    (bsc#1111666).

  - btrfs: fix a block group ref counter leak after failure
    to remove block group (bsc#1175149).

  - btrfs: fix block group leak when removing fails
    (bsc#1175149).

  - btrfs: fix bytes_may_use underflow when running balance
    and scrub in parallel (bsc#1175149).

  - btrfs: fix corrupt log due to concurrent fsync of inodes
    with shared extents (bsc#1175149).

  - btrfs: fix data block group relocation failure due to
    concurrent scrub (bsc#1175149).

  - btrfs: fix double free on ulist after backref resolution
    failure (bsc#1175149).

  - btrfs: fix fatal extent_buffer readahead vs releasepage
    race (bsc#1175149).

  - btrfs: fix memory leaks after failure to lookup
    checksums during inode logging (bsc#1175550).

  - btrfs: fix page leaks after failure to lock page for
    delalloc (bsc#1175149).

  - btrfs: fix race between block group removal and block
    group creation (bsc#1175149).

  - btrfs: fix space_info bytes_may_use underflow after
    nocow buffered write (bsc#1175149).

  - btrfs: fix space_info bytes_may_use underflow during
    space cache writeout (bsc#1175149).

  - btrfs: fix wrong file range cleanup after an error
    filling dealloc range (bsc#1175149).

  - btrfs: inode: fix NULL pointer dereference if inode does
    not need compression (bsc#1174484).

  - btrfs: Open code btrfs_write_and_wait_marked_extents
    (bsc#1175149).

  - btrfs: Rename and export clear_btree_io_tree
    (bsc#1175149).

  - btrfs: treat RWF_(,D)SYNC writes as sync for CRCs
    (bsc#1175493).

  - cfg80211: check vendor command doit pointer before use
    (git-fixes).

  - char: virtio: Select VIRTIO from VIRTIO_CONSOLE
    (bsc#1175667).

  - cifs: document and cleanup dfs mount (bsc#1144333
    bsc#1172428).

  - cifs: Fix an error pointer dereference in cifs_mount()
    (bsc#1144333 bsc#1172428).

  - cifs: fix double free error on share and prefix
    (bsc#1144333 bsc#1172428).

  - cifs: handle empty list of targets in cifs_reconnect()
    (bsc#1144333 bsc#1172428).

  - cifs: handle RESP_GET_DFS_REFERRAL.PathConsumed in
    reconnect (bsc#1144333 bsc#1172428).

  - cifs: merge __(cifs,smb2)_reconnect[_tcon]() into
    cifs_tree_connect() (bsc#1144333 bsc#1172428).

  - cifs: only update prefix path of DFS links in
    cifs_tree_connect() (bsc#1144333 bsc#1172428).

  - cifs: reduce number of referral requests in DFS link
    lookups (bsc#1144333 bsc#1172428).

  - cifs: rename reconn_inval_dfs_target() (bsc#1144333
    bsc#1172428).

  - clk: at91: clk-generated: check best_rate against ranges
    (bsc#1111666).

  - clk: clk-atlas6: fix return value check in
    atlas6_clk_init() (bsc#1111666).

  - clk: iproc: round clock rate to the closest
    (bsc#1111666).

  - clk: spear: Remove uninitialized_var() usage
    (git-fixes).

  - clk: st: Remove uninitialized_var() usage (git-fixes).

  - console: newport_con: fix an issue about leak related
    system resources (git-fixes).

  - crypto: ccp - Fix use of merged scatterlists
    (git-fixes).

  - crypto: cpt - do not sleep of CRYPTO_TFM_REQ_MAY_SLEEP
    was not specified (git-fixes).

  - crypto: qat - fix double free in
    qat_uclo_create_batch_init_list (git-fixes).

  - dev: Defer free of skbs in flush_backlog (git-fixes).

  - device property: Fix the secondary firmware node
    handling in set_primary_fwnode() (git-fixes).

  - devres: keep both device name and resource name in
    pretty name (git-fixes).

  - dlm: Fix kobject memleak (bsc#1175768).

  - dmaengine: fsl-edma: Fix NULL pointer exception in
    fsl_edma_tx_handler (git-fixes).

  - Documentation/networking: Add net DIM documentation
    (bsc#1174852).

  - dpaa2-eth: Fix passing zero to 'PTR_ERR' warning
    (bsc#1175403).

  - dpaa2-eth: free already allocated channels on probe
    defer (bsc#1175404).

  - dpaa2-eth: prevent array underflow in update_cls_rule()
    (bsc#1175405).

  - dpaa_eth: add dropped frames to percpu ethtool stats
    (bsc#1174550).

  - dpaa_eth: add newline in dev_err() msg (bsc#1174550).

  - dpaa_eth: avoid timestamp read on error paths
    (bsc#1175406).

  - dpaa_eth: change DMA device (bsc#1174550).

  - dpaa_eth: cleanup skb_to_contig_fd() (bsc#1174550).

  - dpaa_eth: defer probing after qbman (bsc#1174550).

  - dpaa_eth: extend delays in ndo_stop (bsc#1174550).

  - dpaa_eth: fix DMA mapping leak (bsc#1174550).

  - dpaa_eth: Fix one possible memleak in dpaa_eth_probe
    (bsc#1174550).

  - dpaa_eth: FMan erratum A050385 workaround (bsc#1174550).

  - dpaa_eth: perform DMA unmapping before read
    (bsc#1175407).

  - dpaa_eth: register a device link for the qman portal
    used (bsc#1174550).

  - dpaa_eth: remove netdev_err() for user errors
    (bsc#1174550).

  - dpaa_eth: remove redundant code (bsc#1174550).

  - dpaa_eth: simplify variables used in
    dpaa_cleanup_tx_fd() (bsc#1174550).

  - dpaa_eth: use a page to store the SGT (bsc#1174550).

  - dpaa_eth: use fd information in dpaa_cleanup_tx_fd()
    (bsc#1174550).

  - dpaa_eth: use only one buffer pool per interface
    (bsc#1174550).

  - dpaa_eth: use page backed rx buffers (bsc#1174550).

  - driver core: Avoid binding drivers to dead devices
    (git-fixes).

  - Drivers: hv: balloon: Remove dependencies on guest page
    size (git-fixes).

  - Drivers: hv: vmbus: Fix virt_to_hvpfn() for X86_PAE
    (git-fixes).

  - Drivers: hv: vmbus: Only notify Hyper-V for die events
    that are oops (bsc#1175127, bsc#1175128).

  - Drivers: hv: vmbus: Remove the undesired put_cpu_ptr()
    in hv_synic_cleanup() (git-fixes).

  - drivers/perf: hisi: Fix typo in events attribute array
    (bsc#1175408).

  - drivers/perf: hisi: Fixup one DDRC PMU register offset
    (bsc#1175410).

  - drivers/perf: hisi: Fix wrong value for all counters
    enable (bsc#1175409).

  - drm: Added orientation quirk for ASUS tablet model
    T103HAF (bsc#1111666).

  - drm/amd/display: fix pow() crashing when given base 0
    (git-fixes).

  - drm/amdgpu: avoid dereferencing a NULL pointer
    (bsc#1111666).

  - drm/amdgpu: Fix bug where DPM is not enabled after
    hibernate and resume (bsc#1111666).

  - drm/amdgpu: Fix NULL dereference in dpm sysfs handlers
    (bsc#1113956)

  - drm/amdgpu: Prevent kernel-infoleak in
    amdgpu_info_ioctl() (git-fixes).

  - drm/amdgpu: Replace invalid device ID with a valid
    device ID (bsc#1113956)

  - drm/arm: fix unintentional integer overflow on left
    shift (git-fixes).

  - drm/bridge: dw-hdmi: Do not cleanup i2c adapter and ddc
    ptr in (bsc#1113956)

  - drm/bridge: sil_sii8620: initialize return of
    sii8620_readb (git-fixes).

  - drm/dbi: Fix SPI Type 1 (9-bit) transfer (bsc#1113956)

  - drm/debugfs: fix plain echo to connector 'force'
    attribute (bsc#1111666).

  - drm/etnaviv: Fix error path on failure to enable bus clk
    (git-fixes).

  - drm/etnaviv: fix ref count leak via pm_runtime_get_sync
    (bsc#1111666).

  - drm: fix drm_dp_mst_port refcount leaks in
    drm_dp_mst_allocate_vcpi (bsc#1112178)

  - drm: hold gem reference until object is no longer
    accessed (bsc#1113956)

  - drm/imx: fix use after free (git-fixes).

  - drm/imx: imx-ldb: Disable both channels for split mode
    in enc->disable() (git-fixes).

  - drm/imx: tve: fix regulator_disable error path
    (git-fixes).

  - drm/mipi: use dcs write for
    mipi_dsi_dcs_set_tear_scanline (git-fixes).

  - drm/msm/adreno: fix updating ring fence (git-fixes).

  - drm/msm: ratelimit crtc event overflow error
    (bsc#1111666).

  - drm/nouveau/fbcon: fix module unload when fbcon init has
    failed for some reason (git-fixes).

  - drm/nouveau/fbcon: zero-initialise the mode_cmd2
    structure (git-fixes).

  - drm/nouveau: fix multiple instances of reference count
    leaks (bsc#1111666).

  - drm/panel: otm8009a: Drop unnessary
    backlight_device_unregister() (git-fixes).

  - drm: panel: simple: Fix bpc for LG LB070WV8 panel
    (git-fixes).

  - drm/radeon: disable AGP by default (bsc#1111666).

  - drm/radeon: fix array out-of-bounds read and write
    issues (git-fixes).

  - drm/radeon: Fix reference count leaks caused by
    pm_runtime_get_sync (bsc#1111666).

  - drm/rockchip: fix VOP_WIN_GET macro (bsc#1175411).

  - drm/tilcdc: fix leak & null ref in
    panel_connector_get_modes (bsc#1111666).

  - drm/ttm/nouveau: do not call tt destroy callback on
    alloc failure (bsc#1175232).

  - drm/vmwgfx: Fix two list_for_each loop exit tests
    (bsc#1111666).

  - drm/vmwgfx: Use correct vmw_legacy_display_unit pointer
    (bsc#1111666).

  - drm/xen-front: Fix misused IS_ERR_OR_NULL checks
    (bsc#1065600).

  - ext4: check journal inode extents more carefully
    (bsc#1173485).

  - ext4: do not allow overlapping system zones
    (bsc#1173485).

  - ext4: fix checking of directory entry validity for
    inline directories (bsc#1175771).

  - ext4: handle error of ext4_setup_system_zone() on
    remount (bsc#1173485).

  - fbdev: Detect integer underflow at 'struct
    fbcon_ops'->clear_margins. (bsc#1112178) 

  - firmware: google: check if size is valid when decoding
    VPD data (git-fixes).

  - firmware: google: increment VPD key_len properly
    (git-fixes).

  - fsl/fman: add API to get the device behind a fman port
    (bsc#1174550).

  - fsl/fman: check dereferencing NULL pointer (git-fixes).

  - fsl/fman: detect FMan erratum A050385 (bsc#1174550).

  - fsl/fman: do not touch liodn base regs reserved on
    non-PAMU SoCs (bsc#1174550).

  - fsl/fman: fix dereference null return value (git-fixes).

  - fsl/fman: fix eth hash table allocation (git-fixes).

  - fsl/fman: fix unreachable code (git-fixes).

  - fsl/fman: remove unused struct member (bsc#1174550).

  - fsl/fman: use 32-bit unsigned integer (git-fixes).

  - fuse: fix memleak in cuse_channel_open (bsc#1174926).

  - fuse: fix missing unlock_page in fuse_writepage()
    (bsc#1174904).

  - fuse: Fix parameter for FS_IOC_(GET,SET)FLAGS
    (bsc#1175062).

  - fuse: fix weird page warning (bsc#1175063).

  - fuse: flush dirty data/metadata before non-truncate
    setattr (bsc#1175064).

  - fuse: truncate pending writes on O_TRUNC (bsc#1175065).

  - fuse: verify attributes (bsc#1175066).

  - fuse: verify nlink (bsc#1175067).

  - genetlink: remove genl_bind
    (networking-stable-20_07_17).

  - go7007: add sanity checking for endpoints (git-fixes).

  - gpu: host1x: debug: Fix multiple channels emitting
    messages simultaneously (bsc#1111666).

  - hv_balloon: Balloon up according to request page number
    (git-fixes).

  - hv_balloon: Use a static page for the balloon_up send
    buffer (git-fixes).

  - hv_netvsc: Allow scatter-gather feature to be tunable
    (git-fixes).

  - hv_netvsc: do not use VF device if link is down
    (git-fixes).

  - hv_netvsc: Fix a warning of suspicious RCU usage
    (git-fixes).

  - hv_netvsc: Fix error handling in netvsc_attach()
    (git-fixes).

  - hv_netvsc: Fix extra rcu_read_unlock in
    netvsc_recv_callback() (git-fixes).

  - hv_netvsc: Fix the queue_mapping in netvsc_vf_xmit()
    (git-fixes).

  - hv_netvsc: Fix unwanted wakeup in netvsc_attach()
    (git-fixes).

  - hv_netvsc: flag software created hash value (git-fixes).

  - hv_netvsc: Remove 'unlikely' from netvsc_select_queue
    (git-fixes).

  - i2c: rcar: in slave mode, clear NACK earlier
    (git-fixes).

  - i2c: rcar: slave: only send STOP event when we have been
    addressed (bsc#1111666).

  - i40e: Fix crash during removing i40e driver (git-fixes).

  - i40e: Set RX_ONLY mode for unicast promiscuous on VLAN
    (git-fixes).

  - ibmveth: Fix use of ibmveth in a bridge (bsc#1174387
    ltc#187506).

  - ibmvnic: Fix IRQ mapping disposal in error path
    (bsc#1175112 ltc#187459).

  - ibmvnic fix NULL tx_pools and rx_tools issue at do_reset
    (bsc#1175873 ltc#187922).

  - include/linux/poison.h: remove obsolete comment (git
    fixes (poison)).

  - Input: psmouse - add a newline when printing 'proto' by
    sysfs (git-fixes).

  - Input: sentelic - fix error return when fsp_reg_write
    fails (bsc#1111666).

  - integrity: remove redundant initialization of variable
    ret (git-fixes).

  - ip6_gre: fix null-ptr-deref in ip6gre_init_net()
    (git-fixes).

  - ip6_gre: fix use-after-free in ip6gre_tunnel_lookup()
    (networking-stable-20_06_28).

  - ip6_tunnel: allow not to count pkts on tstats by passing
    dev as NULL (bsc#1175515).

  - ip_tunnel: allow not to count pkts on tstats by setting
    skb's dev to NULL (bsc#1175515).

  - ip_tunnel: Emit events for post-register MTU changes
    (git-fixes).

  - ip_tunnel: fix use-after-free in ip_tunnel_lookup()
    (networking-stable-20_06_28).

  - ip_tunnel: restore binding to ifaces with a large mtu
    (git-fixes).

  - ipv4: fill fl4_icmp_(type,code) in ping_v4_sendmsg
    (networking-stable-20_07_17).

  - ipv4: Silence suspicious RCU usage warning (git-fixes).

  - ipv6: fix memory leaks on IPV6_ADDRFORM path
    (git-fixes).

  - ipvlan: fix device features (git-fixes).

  - ipvs: allow connection reuse for unconfirmed conntrack
    (git-fixes).

  - ipvs: fix refcount usage for conns in ops mode
    (git-fixes).

  - ipvs: fix the connection sync failed in some cases
    (bsc#1174699).

  - irqchip/gic: Atomically update affinity (bsc#1111666).

  - iwlegacy: Check the return value of
    pcie_capability_read_*() (bsc#1111666).

  - jbd2: add the missing unlock_buffer() in the error path
    of jbd2_write_superblock() (bsc#1175772).

  - kABI: genetlink: remove genl_bind (kabi).

  - kabi: hide new parameter of ip6_dst_lookup_flow()
    (bsc#1165629).

  - kabi: mask changes to struct ipv6_stub (bsc#1165629).

  - kernel/cpu_pm: Fix uninitted local in cpu_pm (git fixes
    (kernel/pm)).

  - kernel/relay.c: fix memleak on destroy relay channel
    (git-fixes).

  - kernfs: do not call fsnotify() with name without a
    parent (bsc#1175770).

  - KVM: arm64: Ensure 'params' is initialised when looking
    up sys register (bsc#1133021).

  - KVM: arm64: Stop clobbering x0 for HVC_SOFT_RESTART
    (bsc#1133021).

  - KVM: arm/arm64: Fix young bit from mmu notifier
    (bsc#1133021).

  - KVM: arm/arm64: vgic: Do not rely on the wrong pending
    table (bsc#1133021).

  - KVM: arm/arm64: vgic-its: Fix restoration of unmapped
    collections (bsc#1133021).

  - KVM: arm: Fix DFSR setting for non-LPAE aarch32 guests
    (bsc#1133021).

  - KVM: arm: Make inject_abt32() inject an external abort
    instead (bsc#1133021).

  - kvm: Change offset in kvm_write_guest_offset_cached to
    unsigned (bsc#1133021).

  - KVM: Check for a bad hva before dropping into the ghc
    slow path (bsc#1133021).

  - KVM: PPC: Book3S PR: Remove uninitialized_var() usage
    (bsc#1065729).

  - l2tp: remove skb_dst_set() from l2tp_xmit_skb()
    (networking-stable-20_07_17).

  - leds: 88pm860x: fix use-after-free on unbind
    (git-fixes).

  - leds: core: Flush scheduled work for system suspend
    (git-fixes).

  - leds: da903x: fix use-after-free on unbind (git-fixes).

  - leds: lm3533: fix use-after-free on unbind (git-fixes).

  - leds: lm355x: avoid enum conversion warning (git-fixes).

  - leds: wm831x-status: fix use-after-free on unbind
    (git-fixes).

  - lib/dim: Fix -Wunused-const-variable warnings
    (bsc#1174852).

  - lib: dimlib: fix help text typos (bsc#1174852).

  - linux/dim: Add completions count to dim_sample
    (bsc#1174852).

  - linux/dim: Fix overflow in dim calculation
    (bsc#1174852).

  - linux/dim: Move implementation to .c files
    (bsc#1174852).

  - linux/dim: Move logic to dim.h (bsc#1174852).

  - linux/dim: Remove 'net' prefix from internal DIM members
    (bsc#1174852).

  - linux/dim: Rename externally exposed macros
    (bsc#1174852).

  - linux/dim: Rename externally used net_dim members
    (bsc#1174852).

  - linux/dim: Rename net_dim_sample() to
    net_dim_update_sample() (bsc#1174852).

  - liquidio: Fix wrong return value in cn23xx_get_pf_num()
    (git-fixes).

  - llc: make sure applications use ARPHRD_ETHER
    (networking-stable-20_07_17).

  - mac80211: mesh: Free ie data when leaving mesh
    (git-fixes).

  - mac80211: mesh: Free pending skb when destroying a mpath
    (git-fixes).

  - MAINTAINERS: add entry for Dynamic Interrupt Moderation
    (bsc#1174852).

  - md-cluster: Fix potential error pointer dereference in
    resize_bitmaps() (git-fixes).

  - md/raid5: Fix Force reconstruct-write io stuck in
    degraded raid5 (git-fixes).

  - media: budget-core: Improve exception handling in
    budget_register() (git-fixes).

  - media: exynos4-is: Add missed check for
    pinctrl_lookup_state() (git-fixes).

  - media: firewire: Using uninitialized values in
    node_probe() (git-fixes).

  - media: omap3isp: Add missed v4l2_ctrl_handler_free() for
    preview_init_entities() (git-fixes).

  - media: vpss: clean up resources in init (git-fixes).

  - mfd: arizona: Ensure 32k clock is put on driver unbind
    and error (git-fixes).

  - mfd: dln2: Run event handler loop under spinlock
    (git-fixes).

  - mfd: rk808: Fix RK818 ID template (bsc#1175412).

  - mld: fix memory leak in ipv6_mc_destroy_dev()
    (networking-stable-20_06_28).

  - mm: filemap: clear idle flag for writes (bsc#1175769).

  - mm/migrate.c: add missing flush_dcache_page for
    non-mapped page migrate (git fixes (mm/migrate)).

  - mm/mmu_notifier: use hlist_add_head_rcu() (git fixes
    (mm/mmu_notifiers)).

  - mm: remove VM_BUG_ON(PageSlab()) from page_mapcount()
    (git fixes (mm/compaction)).

  - mm/rmap.c: do not reuse anon_vma if we just want a copy
    (git fixes (mm/rmap)).

  - mm/shmem.c: cast the type of unmap_start to u64 (git
    fixes (mm/shmem)).

  - mm, thp: fix defrag setting if newline is not used (git
    fixes (mm/thp)).

  - mm/vunmap: add cond_resched() in vunmap_pmd_range
    (bsc#1175654 ltc#184617).

  - mtd: spi-nor: Fix an error code in spi_nor_read_raw()
    (bsc#1175413).

  - mtd: spi-nor: fix kernel-doc for spi_nor::info
    (bsc#1175414).

  - mtd: spi-nor: fix kernel-doc for spi_nor::reg_proto
    (bsc#1175415).

  - mtd: spi-nor: fix silent truncation in
    spi_nor_read_raw() (bsc#1175416).

  - mwifiex: Prevent memory corruption handling keys
    (git-fixes).

  - net: Added pointer check for dst->ops->neigh_lookup in
    dst_neigh_lookup_skb (git-fixes).

  - net: bridge: enfore alignment for ethernet address
    (networking-stable-20_06_28).

  - net: core: reduce recursion limit value
    (networking-stable-20_06_28).

  - net: Do not clear the sock TX queue in sk_set_socket()
    (networking-stable-20_06_28).

  - net: dsa: b53: check for timeout (git-fixes).

  - net: ena: Add first_interrupt field to napi struct
    (bsc#1174852).

  - net: ena: add reserved PCI device ID (bsc#1174852).

  - net: ena: add support for reporting of packet drops
    (bsc#1174852).

  - net: ena: add support for the rx offset feature
    (bsc#1174852).

  - net: ena: add support for traffic mirroring
    (bsc#1174852).

  - net: ena: add unmask interrupts statistics to ethtool
    (bsc#1174852).

  - net: ena: allow setting the hash function without
    changing the key (bsc#1174852).

  - net: ena: avoid unnecessary admin command when RSS
    function set fails (bsc#1174852).

  - net: ena: avoid unnecessary rearming of interrupt vector
    when busy-polling (bsc#1174852).

  - net: ena: change default RSS hash function to Toeplitz
    (bsc#1174852).

  - net: ena: change num_queues to num_io_queues for clarity
    and consistency (bsc#1174852).

  - net: ena: changes to RSS hash key allocation
    (bsc#1174852).

  - net: ena: Change WARN_ON expression in
    ena_del_napi_in_range() (bsc#1174852).

  - net: ena: clean up indentation issue (bsc#1174852).

  - net: ena: cosmetic: change ena_com_stats_admin stats to
    u64 (bsc#1174852).

  - net: ena: cosmetic: code reorderings (bsc#1174852).

  - net: ena: cosmetic: extract code to
    ena_indirection_table_set() (bsc#1174852).

  - net: ena: cosmetic: fix line break issues (bsc#1174852).

  - net: ena: cosmetic: fix spacing issues (bsc#1174852).

  - net: ena: cosmetic: fix spelling and grammar mistakes in
    comments (bsc#1174852).

  - net: ena: cosmetic: minor code changes (bsc#1174852).

  - net: ena: cosmetic: remove unnecessary code
    (bsc#1174852).

  - net: ena: cosmetic: remove unnecessary spaces and tabs
    in ena_com.h macros (bsc#1174852).

  - net: ena: cosmetic: rename
    ena_update_tx/rx_rings_intr_moderation() (bsc#1174852).

  - net: ena: cosmetic: satisfy gcc warning (bsc#1174852).

  - net: ena: cosmetic: set queue sizes to u32 for
    consistency (bsc#1174852).

  - net: ena: drop superfluous prototype (bsc#1174852).

  - net: ena: enable support of rss hash key and function
    changes (bsc#1174852).

  - net: ena: enable the interrupt_moderation in
    driver_supported_features (bsc#1174852).

  - net: ena: ethtool: clean up minor indentation issue
    (bsc#1174852).

  - net: ena: ethtool: get_channels: use combined only
    (bsc#1174852).

  - net: ena: ethtool: remove redundant non-zero check on rc
    (bsc#1174852).

  - net: ena: ethtool: support set_channels callback
    (bsc#1174852).

  - net/ena: Fix build warning in ena_xdp_set()
    (bsc#1174852).

  - net: ena: fix ena_com_comp_status_to_errno() return
    value (bsc#1174852).

  - net: ena: fix error returning in
    ena_com_get_hash_function() (bsc#1174852).

  - net: ena: fix incorrect setting of the number of msix
    vectors (bsc#1174852).

  - net: ena: fix incorrect update of intr_delay_resolution
    (bsc#1174852).

  - net: ena: fix request of incorrect number of IRQ vectors
    (bsc#1174852).

  - net: ena: fix update of interrupt moderation register
    (bsc#1174852).

  - net: ena: Fix using plain integer as NULL pointer in
    ena_init_napi_in_range (bsc#1174852).

  - net: ena: implement XDP drop support (bsc#1174852).

  - net: ena: Implement XDP_TX action (bsc#1174852).

  - net: ena: make ethtool -l show correct max number of
    queues (bsc#1174852).

  - net: ena: Make missed_tx stat incremental (bsc#1083548).

  - net: ena: Make some functions static (bsc#1174852).

  - net: ena: move llq configuration from ena_probe to
    ena_device_init() (bsc#1174852).

  - net: ena: multiple queue creation related cleanups
    (bsc#1174852).

  - net: ena: Prevent reset after device destruction
    (bsc#1083548).

  - net: ena: reduce driver load time (bsc#1174852).

  - net: ena: remove all old adaptive rx interrupt
    moderation code from ena_com (bsc#1174852).

  - net: ena: remove code duplication in
    ena_com_update_nonadaptive_moderation_interval _*()
    (bsc#1174852).

  - net: ena: remove code that does nothing (bsc#1174852).

  - net: ena: remove ena_restore_ethtool_params() and
    relevant fields (bsc#1174852).

  - net: ena: remove old adaptive interrupt moderation code
    from ena_netdev (bsc#1174852).

  - net: ena: remove redundant print of number of queues
    (bsc#1174852).

  - net: ena: remove set but not used variable 'hash_key'
    (bsc#1174852).

  - net: ena: remove set but not used variable 'rx_ring'
    (bsc#1174852).

  - net: ena: rename ena_com_free_desc to make API more
    uniform (bsc#1174852).

  - net: ena: Select DIMLIB for ENA_ETHERNET (bsc#1174852).

  - net: ena: simplify
    ena_com_update_intr_delay_resolution() (bsc#1174852).

  - net: ena: support new LLQ acceleration mode
    (bsc#1174852).

  - net: ena: switch to dim algorithm for rx adaptive
    interrupt moderation (bsc#1174852).

  - net: ena: use explicit variable size for clarity
    (bsc#1174852).

  - net: ena: use SHUTDOWN as reset reason when closing
    interface (bsc#1174852).

  - net: ena: xdp: update napi budget for DROP and ABORTED
    (bsc#1174852).

  - net: ena: xdp: XDP_TX: fix memory leak (bsc#1174852).

  - net: ethernet: aquantia: Fix wrong return value
    (git-fixes).

  - net: ethernet: broadcom: have drivers select DIMLIB as
    needed (bsc#1174852).

  - net: ethernet: stmmac: Disable hardware multicast filter
    (git-fixes).

  - net: fec: correct the error path for regulator disable
    in probe (git-fixes).

  - netfilter: x_tables: add counters allocation wrapper
    (git-fixes).

  - netfilter: x_tables: cap allocations at 512 mbyte
    (git-fixes).

  - netfilter: x_tables: limit allocation requests for blob
    rule heads (git-fixes).

  - net: Fix a documentation bug wrt.
    ip_unprivileged_port_start (git-fixes). (SLES tuning
    guide refers to ip-sysctl.txt.)

  - net: fix memleak in register_netdevice()
    (networking-stable-20_06_28).

  - net: Fix the arp error in some cases
    (networking-stable-20_06_28).

  - net: gre: recompute gre csum for sctp over gre tunnels
    (git-fixes).

  - net: increment xmit_recursion level in dev_direct_xmit()
    (networking-stable-20_06_28).

  - net: ip6_gre: Request headroom in __gre6_xmit()
    (git-fixes).

  - net: lan78xx: add missing endpoint sanity check
    (git-fixes).

  - net: lan78xx: fix transfer-buffer memory leak
    (git-fixes).

  - net: make symbol 'flush_works' static (git-fixes).

  - net/mlx5: Delete extra dump stack that gives nothing
    (git-fixes).

  - net/mlx5e: vxlan: Use RCU for vxlan table lookup
    (git-fixes).

  - net: mvpp2: fix memory leak in mvpp2_rx (git-fixes).

  - net: netsec: Fix signedness bug in netsec_probe()
    (bsc#1175417).

  - net: netsec: initialize tx ring on ndo_open
    (bsc#1175418).

  - net: phy: Check harder for errors in get_phy_id()
    (bsc#1111666).

  - net: qcom/emac: add missed clk_disable_unprepare in
    error path of emac_clks_phase1_init (git-fixes).

  - net: Set fput_needed iff FDPUT_FPUT is set (git-fixes).

  - net: socionext: Fix a signedness bug in ave_probe()
    (bsc#1175419).

  - net: socionext: replace napi_alloc_frag with the netdev
    variant on init (bsc#1175420).

  - net: spider_net: Fix the size used in a
    'dma_free_coherent()' call (git-fixes).

  - net: stmmac: dwmac1000: provide multicast filter
    fallback (git-fixes).

  - net: stmmac: Fix RX packet size > 8191 (git-fixes).

  - net: udp: Fix wrong clean up for IS_UDPLITE macro
    (git-fixes).

  - net: update net_dim documentation after rename
    (bsc#1174852).

  - net: usb: ax88179_178a: fix packet alignment padding
    (networking-stable-20_06_28).

  - net: usb: qmi_wwan: add support for Quectel EG95 LTE
    modem (networking-stable-20_07_17).

  - netvsc: unshare skb in VF rx handler (git-fixes).

  - nfc: nci: add missed destroy_workqueue in
    nci_register_device (git-fixes).

  - NTB: Fix an error in get link status (git-fixes).

  - ntb_netdev: fix sleep time mismatch (git-fixes).

  - NTB: ntb_transport: Use scnprintf() for avoiding
    potential buffer overflow (git-fixes).

  - nvme: explicitly update mpath disk capacity on
    revalidation (git-fixes).

  - nvme: fix possible deadlock when I/O is blocked
    (git-fixes).

  - nvme-multipath: do not fall back to __nvme_find_path()
    for non-optimized paths (bsc#1172108).

  - nvme-multipath: fix logic for non-optimized paths
    (bsc#1172108).

  - nvme-multipath: round-robin: eliminate 'fallback'
    variable (bsc#1172108).

  - nvme: multipath: round-robin: fix single non-optimized
    path case (bsc#1172108).

  - obsolete_kmp: provide newer version than the obsoleted
    one (boo#1170232).

  - ocfs2: add trimfs dlm lock resource (bsc#1175228).

  - ocfs2: add trimfs lock to avoid duplicated trims in
    cluster (bsc#1175228).

  - ocfs2: avoid inode removal while nfsd is accessing it
    (bsc#1172963).

  - ocfs2: change slot number type s16 to u16 (bsc#1175786).

  - ocfs2: fix panic on nfs server over ocfs2 (bsc#1172963).

  - ocfs2: fix remounting needed after setfacl command
    (bsc#1173954).

  - ocfs2: fix the application IO timeout when fstrim is
    running (bsc#1175228).

  - ocfs2: fix value of OCFS2_INVALID_SLOT (bsc#1175767).

  - ocfs2: load global_inode_alloc (bsc#1172963).

  - omapfb: dss: Fix max fclk divider for omap36xx
    (bsc#1113956)

  - openvswitch: Prevent kernel-infoleak in ovs_ct_put_key()
    (git-fixes).

  - PCI/ASPM: Add missing newline in sysfs 'policy'
    (git-fixes).

  - PCI: dwc: Move interrupt acking into the proper callback
    (bsc#1175666).

  - PCI: Fix pci_cfg_wait queue locking problem (git-fixes).

  - PCI: hotplug: ACPI: Fix context refcounting in
    acpiphp_grab_context() (git-fixes).

  - PCI: hv: Fix a timing issue which causes kdump to fail
    occasionally (bsc#1172871, bsc#1172872, git-fixes).

  - PCI: Release IVRS table in AMD ACS quirk (git-fixes).

  - PCI: switchtec: Add missing __iomem and __user tags to
    fix sparse warnings (git-fixes).

  - PCI: switchtec: Add missing __iomem tag to fix sparse
    warnings (git-fixes).

  - phy: sun4i-usb: fix dereference of pointer phy0 before
    it is null checked (git-fixes).

  - pinctrl: single: fix function name in documentation
    (git-fixes).

  - pinctrl-single: fix pcs_parse_pinconf() return value
    (git-fixes).

  - platform/x86: intel-hid: Fix return value check in
    check_acpi_dev() (git-fixes).

  - platform/x86: intel-vbtn: Fix return value check in
    check_acpi_dev() (git-fixes).

  - PM / CPU: replace raw_notifier with atomic_notifier (git
    fixes (kernel/pm)).

  - PM / devfreq: rk3399_dmc: Add missing of_node_put()
    (bsc#1175668).

  - PM / devfreq: rk3399_dmc: Disable devfreq-event device
    when fails.

  - PM / devfreq: rk3399_dmc: Fix kernel oops when
    rockchip,pmu is absent (bsc#1175668).

  - PM: sleep: core: Fix the handling of pending runtime
    resume requests (git-fixes).

  - powerpc/64s: Do not init FSCR_DSCR in __init_FSCR()
    (bsc#1065729).

  - powerpc/64s: Fix early_init_mmu section mismatch
    (bsc#1065729).

  - powerpc: Allow 4224 bytes of stack expansion for the
    signal frame (bsc#1065729).

  - powerpc/book3s64/pkeys: Use PVR check instead of cpu
    feature (bsc#1065729).

  - powerpc/boot: Fix CONFIG_PPC_MPC52XX references
    (bsc#1065729).

  - powerpc/eeh: Fix pseries_eeh_configure_bridge()
    (bsc#1174689).

  - powerpc/nvdimm: Use HCALL error as the return value
    (bsc#1175284).

  - powerpc/nvdimm: use H_SCM_QUERY hcall on H_OVERLAP error
    (bsc#1175284).

  - powerpc/perf: Fix missing is_sier_aviable() during build
    (bsc#1065729).

  - powerpc/pseries: Do not initiate shutdown when system is
    running on UPS (bsc#1175440 ltc#187574).

  - powerpc/pseries/hotplug-cpu: Remove double free in error
    path (bsc#1065729).

  - powerpc/pseries/hotplug-cpu: wait indefinitely for vCPU
    death (bsc#1085030 ltC#165630).

  - powerpc/pseries: PCIE PHB reset (bsc#1174689).

  - powerpc/pseries: remove cede offline state for CPUs
    (bsc#1065729).

  - powerpc/rtas: do not online CPUs for partition suspend
    (bsc#1065729).

  - powerpc/vdso: Fix vdso cpu truncation (bsc#1065729).

  - power: supply: check if calc_soc succeeded in
    pm860x_init_battery (git-fixes).

  - pseries: Fix 64 bit logical memory block panic
    (bsc#1065729).

  - pwm: bcm-iproc: handle clk_get_rate() return
    (git-fixes).

  - rds: Prevent kernel-infoleak in rds_notify_queue_get()
    (git-fixes).

  - regulator: gpio: Honor regulator-boot-on property
    (git-fixes).

  - Revert 'ALSA: hda: call runtime_allow() for all hda
    controllers' (bsc#1111666).

  - Revert 'drm/amdgpu: Fix NULL dereference in dpm sysfs
    handlers' (bsc#1113956) &#9;* refresh for context
    changes

  - Revert 'ocfs2: avoid inode removal while nfsd is
    accessing it' This reverts commit
    9e096c72476eda333a9998ff464580c00ff59c83.

  - Revert 'ocfs2: fix panic on nfs server over ocfs2
    (bsc#1172963).' This reverts commit
    0bf6e248f93736b3f17f399b4a8f64ffa30d371e.

  - Revert 'ocfs2: load global_inode_alloc (bsc#1172963).'
    This reverts commit
    fc476497b53f967dc615b9cbad9427ba3107b5c4.

  - Revert 'scsi: qla2xxx: Disable T10-DIF feature with
    FC-NVMe during probe' (bsc#1171688 bsc#1174003).

  - Revert 'scsi: qla2xxx: Fix crash on
    qla2x00_mailbox_command' (bsc#1171688 bsc#1174003).

  - Revert 'xen/balloon: Fix crash when ballooning on x86 32
    bit PAE' (bsc#1065600).

  - rocker: fix incorrect error handling in dma_rings_init
    (networking-stable-20_06_28).

  - rpm/check-for-config-changes: Ignore
    CONFIG_CC_VERSION_TEXT

  - rpm/check-for-config-changes: Ignore CONFIG_LD_VERSION

  - rpm/kernel-source.spec.in: Add obsolete_rebuilds
    (boo#1172073).

  - rtlwifi: rtl8192cu: Remove uninitialized_var() usage
    (git-fixes).

  - s390, dcssblk: kaddr and pfn can be NULL to
    ->direct_access() (bsc#1174873).

  - sched: consistently handle layer3 header accesses in the
    presence of VLANs (networking-stable-20_07_17).

  - scsi: dh: Add Fujitsu device to devinfo and dh lists
    (bsc#1174026).

  - scsi: Fix trivial spelling (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Add more BUILD_BUG_ON() statements
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Address a set of sparse warnings
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Allow ql2xextended_error_logging special
    value 1 to be set anytime (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Cast explicitly to uint16_t / uint32_t
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Change in PUREX to handle FPIN ELS
    requests (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Change (RD,WRT)_REG_*() function names
    from upper case into lower case (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Change two hardcoded constants into
    offsetof() / sizeof() expressions (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Check if FW supports MQ before enabling
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Check the size of struct fcp_hdr at
    compile time (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix a Coverity complaint in
    qla2100_fw_dump() (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix endianness annotations in header
    files (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix endianness annotations in source
    files (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix failure message in qlt_disable_vha()
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix issue with adapter's stopping state
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix login timeout (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Fix MPI failure AEN (8200) handling
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix NULL pointer access during disconnect
    from subsystem (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix spelling of a variable name
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix the code that reads from mailbox
    registers (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix warning after FC target reset
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix WARN_ON in qla_nvme_register_hba
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Flush all sessions on zone disable
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Flush I/O on zone disable (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Increase the size of struct
    qla_fcp_prio_cfg to FCP_PRIO_CFG_SIZE (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Indicate correct supported speeds for
    Mezz card (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Initialize 'n' before using it
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Introduce a function for computing the
    debug message prefix (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Keep initiator ports after RSCN
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: make 1-bit bit-fields unsigned int
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make a gap in struct qla2xxx_offld_chain
    explicit (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make __qla2x00_alloc_iocbs() initialize
    32 bits of request_t.handle (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qla2x00_restart_isp() easier to read
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qla82xx_flash_wait_write_finish()
    easier to read (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qlafx00_process_aen() return void
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make qla_set_ini_mode() return void
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Reduce noisy debug message (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Remove an unused function (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Remove a superfluous cast (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Remove return value from qla_nvme_ls()
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Remove the __packed annotation from
    struct fcp_hdr and fcp_hdr_le (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: SAN congestion management implementation
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Simplify the functions for dumping
    firmware (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Sort BUILD_BUG_ON() statements
    alphabetically (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Split qla2x00_configure_local_loop()
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use ARRAY_SIZE() instead of open-coding
    it (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use make_handle() instead of open-coding
    it (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use MBX_TOV_SECONDS for mailbox command
    timeout values (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use register names instead of register
    offsets (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use true, false for ha->fw_dumped
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Use true, false for need_mpi_reset
    (bsc#1171688 bsc#1174003).

  - scsi: smartpqi: add bay identifier (bsc#1172418).

  - scsi: smartpqi: add gigabyte controller (bsc#1172418).

  - scsi: smartpqi: add id support for SmartRAID 3152-8i
    (bsc#1172418).

  - scsi: smartpqi: add inquiry timeouts (bsc#1172418).

  - scsi: smartpqi: add module param for exposure order
    (bsc#1172418).

  - scsi: smartpqi: add module param to hide vsep
    (bsc#1172418).

  - scsi: smartpqi: add new pci ids (bsc#1172418).

  - scsi: smartpqi: add pci ids for fiberhome controller
    (bsc#1172418).

  - scsi: smartpqi: add RAID bypass counter (bsc#1172418).

  - scsi: smartpqi: add sysfs entries (bsc#1172418).

  - scsi: smartpqi: Align driver syntax with oob
    (bsc#1172418).

  - scsi: smartpqi: avoid crashing kernel for controller
    issues (bsc#1172418).

  - scsi: smartpqi: bump version (bsc#1172418).

  - scsi: smartpqi: bump version (bsc#1172418).

  - scsi: smartpqi: bump version to 1.2.16-010
    (bsc#1172418).

  - scsi: smartpqi: change TMF timeout from 60 to 30 seconds
    (bsc#1172418).

  - scsi: smartpqi: correct hang when deleting 32 lds
    (bsc#1172418).

  - scsi: smartpqi: correct REGNEWD return status
    (bsc#1172418).

  - scsi: smartpqi: correct syntax issue (bsc#1172418).

  - scsi: smartpqi: fix call trace in device discovery
    (bsc#1172418).

  - scsi: smartpqi: fix controller lockup observed during
    force reboot (bsc#1172418).

  - scsi: smartpqi: fix LUN reset when fw bkgnd thread is
    hung (bsc#1172418).

  - scsi: smartpqi: fix problem with unique ID for physical
    device (bsc#1172418).

  - scsi: smartpqi: identify physical devices without
    issuing INQUIRY (bsc#1172418).

  - scsi: smartpqi: properly set both the DMA mask and the
    coherent DMA mask (bsc#1172418).

  - scsi: smartpqi: remove unused manifest constants
    (bsc#1172418).

  - scsi: smartpqi: Reporting unhandled SCSI errors
    (bsc#1172418).

  - scsi: smartpqi: support device deletion via sysfs
    (bsc#1172418).

  - scsi: smartpqi: update copyright (bsc#1172418).

  - scsi: smartpqi: update logical volume size after
    expansion (bsc#1172418).

  - scsi: smartpqi: Use scnprintf() for avoiding potential
    buffer overflow (bsc#1172418).

  - scsi: storvsc: Correctly set number of hardware queues
    for IDE disk (git-fixes).

  - scsi: target/iblock: fix WRITE SAME zeroing
    (bsc#1169790).

  - sctp: Do not advertise IPv4 addresses if ipv6only is set
    on the socket (networking-stable-20_06_28).

  - selftests/livepatch: fix mem leaks in
    test-klp-shadow-vars (bsc#1071995).

  - selftests/livepatch: more verification in
    test-klp-shadow-vars (bsc#1071995).

  - selftests/livepatch: rework test-klp-shadow-vars
    (bsc#1071995).

  - selftests/livepatch: simplify test-klp-callbacks busy
    target tests (bsc#1071995).

  - serial: 8250: change lock order in
    serial8250_do_startup() (git-fixes).

  - serial: pl011: Do not leak amba_ports entry on driver
    register error (git-fixes).

  - serial: pl011: Fix oops on -EPROBE_DEFER (git-fixes).

  - Set VIRTIO_CONSOLE=y (bsc#1175667).

  - sign also s390x kernel images (bsc#1163524)

  - soc: fsl: qbman: allow registering a device link for the
    portal user (bsc#1174550).

  - soc: fsl: qbman_portals: add APIs to retrieve the
    probing status (bsc#1174550).

  - spi: davinci: Remove uninitialized_var() usage
    (git-fixes).

  - spi: lantiq: fix: Rx overflow error in full duplex mode
    (git-fixes).

  - spi: nxp-fspi: Ensure width is respected in spi-mem
    operations (bsc#1175421).

  - spi: spi-fsl-dspi: Fix 16-bit word order in 32-bit XSPI
    mode (bsc#1175422).

  - spi: spi-mem: export spi_mem_default_supports_op()
    (bsc#1175421).

  - spi: sun4i: update max transfer size reported
    (git-fixes).

  - staging: comedi: addi_apci_1032: check
    INSN_CONFIG_DIGITAL_TRIG shift (git-fixes).

  - staging: comedi: addi_apci_1500: check
    INSN_CONFIG_DIGITAL_TRIG shift (git-fixes).

  - staging: comedi: addi_apci_1564: check
    INSN_CONFIG_DIGITAL_TRIG shift (git-fixes).

  - staging: comedi: ni_6527: fix INSN_CONFIG_DIGITAL_TRIG
    support (git-fixes).

  - staging: fsl-dpaa2: ethsw: Add missing netdevice check
    (bsc#1175423).

  - staging: rtl8192u: fix a dubious looking mask before a
    shift (git-fixes).

  - Staging: rtl8723bs: prevent buffer overflow in
    update_sta_support_rate() (git-fixes).

  - staging/speakup: fix get_word non-space look-ahead
    (git-fixes).

  - tcp_cubic: fix spurious HYSTART_DELAY exit upon drop in
    min RTT (networking-stable-20_06_28).

  - tcp: grow window for OOO packets only for SACK flows
    (networking-stable-20_06_28).

  - tcp: make sure listeners do not initialize
    congestion-control state (networking-stable-20_07_17).

  - tcp: md5: add missing memory barriers in
    tcp_md5_do_add()/tcp_md5_hash_key()
    (networking-stable-20_07_17).

  - tcp: md5: do not send silly options in SYNCOOKIES
    (networking-stable-20_07_17).

  - tcp: md5: refine tcp_md5_do_add()/tcp_md5_hash_key()
    barriers (networking-stable-20_07_17).

  - tracepoint: Mark __tracepoint_string's __used
    (git-fixes).

  - tracing: Use trace_sched_process_free() instead of
    exit() for pid tracing (git-fixes).

  - tty: serial: fsl_lpuart: add imx8qxp support
    (bsc#1175670).

  - tty: serial: fsl_lpuart: free IDs allocated by IDA
    (bsc#1175670).

  - Update patch reference for a tipc fix patch
    (bsc#1175515)

  - USB: cdc-acm: rework notification_buffer resizing
    (git-fixes).

  - usb: gadget: f_tcm: Fix some resource leaks in some
    error paths (git-fixes).

  - usb: host: ohci-exynos: Fix error handling in
    exynos_ohci_probe() (git-fixes).

  - USB: Ignore UAS for JMicron JMS567 ATA/ATAPI Bridge
    (git-fixes).

  - USB: iowarrior: fix up report size handling for some
    devices (git-fixes).

  - usbip: tools: fix module name in man page (git-fixes).

  - USB: rename USB quirk to USB_QUIRK_ENDPOINT_IGNORE
    (git-fixes).

  - USB: serial: cp210x: enable usb generic
    throttle/unthrottle (git-fixes).

  - USB: serial: cp210x: re-enable auto-RTS on open
    (git-fixes).

  - USB: serial: ftdi_sio: clean up receive processing
    (git-fixes).

  - USB: serial: ftdi_sio: fix break and sysrq handling
    (git-fixes).

  - USB: serial: ftdi_sio: make process-packet buffer
    unsigned (git-fixes).

  - USB: serial: iuu_phoenix: fix led-activity helpers
    (git-fixes).

  - USB: serial: qcserial: add EM7305 QDL product ID
    (git-fixes).

  - usb: xhci: define IDs for various ASMedia host
    controllers (git-fixes).

  - usb: xhci: Fix ASM2142/ASM3142 DMA addressing
    (git-fixes).

  - usb: xhci: Fix ASMedia ASM1142 DMA addressing
    (git-fixes).

  - usb: xhci-mtk: fix the failure of bandwidth allocation
    (git-fixes).

  - VFS: Check rename_lock in lookup_fast() (bsc#1174734).

  - video: fbdev: sm712fb: fix an issue about iounmap for a
    wrong address (git-fixes).

  - video: pxafb: Fix the function used to balance a
    'dma_alloc_coherent()' call (git-fixes).

  - vlan: consolidate VLAN parsing code and limit max
    parsing depth (networking-stable-20_07_17).

  - vmxnet3: use correct tcp hdr length when packet is
    encapsulated (bsc#1175199).

  - watchdog: f71808e_wdt: clear watchdog timeout occurred
    flag (bsc#1111666).

  - watchdog: f71808e_wdt: indicate WDIOF_CARDRESET support
    in watchdog_info.options (bsc#1111666).

  - watchdog: f71808e_wdt: remove use of wrong watchdog_info
    option (bsc#1111666).

  - wl1251: fix always return 0 error (git-fixes).

  - x86/hyperv: Create and use Hyper-V page definitions
    (git-fixes).

  - x86/hyper-v: Fix overflow bug in fill_gva_list()
    (git-fixes).

  - x86/hyperv: Make hv_vcpu_is_preempted() visible
    (git-fixes).

  - xen/balloon: fix accounting in alloc_xenballooned_pages
    error path (bsc#1065600).

  - xen/balloon: make the balloon wait interruptible
    (bsc#1065600).

  - xfrm: check id proto in validate_tmpl() (git-fixes).

  - xfrm: clean up xfrm protocol checks (git-fixes).

  - xfrm_user: uncoditionally validate esn replay attribute
    struct (git-fixes).

  - xfs: fix inode allocation block res calculation
    precedence (git-fixes).

  - xfs: fix reflink quota reservation accounting error
    (git-fixes)."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175873"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.63.1") ) flag++;

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
