#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2112.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(143398);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-12351",
    "CVE-2020-12352",
    "CVE-2020-14351",
    "CVE-2020-16120",
    "CVE-2020-24490",
    "CVE-2020-25212",
    "CVE-2020-25285",
    "CVE-2020-25641",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25704",
    "CVE-2020-25705",
    "CVE-2020-8694"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-2112)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-12351: Fixed a type confusion while processing
    AMP packets aka 'BleedingTooth' aka 'BadKarma'
    (bsc#1177724).

  - CVE-2020-24490: Fixed a heap buffer overflow when
    processing extended advertising report events aka
    'BleedingTooth' aka 'BadVibes' (bsc#1177726).

  - CVE-2020-12352: Fixed an information leak when
    processing certain AMP packets aka 'BleedingTooth' aka
    'BadChoice' (bsc#1177725).

  - CVE-2020-25212: A TOCTOU mismatch in the NFS client code
    in the Linux kernel could be used by local attackers to
    corrupt memory or possibly have unspecified other impact
    because a size check is in fs/nfs/nfs4proc.c instead of
    fs/nfs/nfs4xdr.c, aka CID-b4487b935452 (bnc#1176381).

  - CVE-2020-25645: Traffic between two Geneve endpoints may
    be unencrypted when IPsec is configured to encrypt
    traffic for the specific UDP port used by the GENEVE
    tunnel allowing anyone between the two endpoints to read
    the traffic unencrypted. The main threat from this
    vulnerability is to data confidentiality (bnc#1177511).

  - CVE-2020-25643: Memory corruption and a read overflow is
    caused by improper input validation in the
    ppp_cp_parse_cr function which can cause the system to
    crash or cause a denial of service. The highest threat
    from this vulnerability is to data confidentiality and
    integrity as well as system availability (bnc#1177206).

  - CVE-2020-25641: A zero-length biovec request issued by
    the block subsystem could cause the kernel to enter an
    infinite loop, causing a denial of service. This flaw
    allowed a local attacker with basic privileges to issue
    requests to a block device, resulting in a denial of
    service. The highest threat from this vulnerability is
    to system availability (bnc#1177121).

  - CVE-2020-25704: Fixed a memory leak in
    perf_event_parse_addr_filter() (bsc#1178393).

  - CVE-2020-25668: Make FONTX ioctl use the tty pointer
    they were actually passed (bsc#1178123).

  - CVE-2020-25656: Extend func_buf_lock to readers
    (bnc#1177766).

  - CVE-2020-25285: Fixed a race condition between hugetlb
    sysctl handlers in mm/hugetlb.c in the Linux kernel
    could be used by local attackers to corrupt memory,
    cause a NULL pointer dereference, or possibly have
    unspecified other impact, aka CID-17743798d812
    (bnc#1176485).

  - CVE-2020-14351: Fixed race in the perf_mmap_close()
    function (bsc#1177086).

  - CVE-2020-8694: Restrict energy meter to root access
    (bsc#1170415).

  - CVE-2020-16120: Check permission to open real file in
    overlayfs (bsc#1177470).

  - CVE-2020-25705: A ICMP global rate limiting side-channel
    was removed which could lead to e.g. the SADDNS attack
    (bsc#1175721)

The following non-security bugs were fixed :

  - 9p: Fix memory leak in v9fs_mount (git-fixes).

  - ACPI: Always build evged in (git-fixes).

  - ACPI: button: fix handling lid state changes when input
    device closed (git-fixes).

  - ACPI: configfs: Add missing config_item_put() to fix
    refcount leak (git-fixes).

  - acpi-cpufreq: Honor _PSD table setting on new AMD CPUs
    (git-fixes).

  - ACPI: debug: do not allow debugging when ACPI is
    disabled (git-fixes).

  - ACPI: EC: Reference count query handlers under lock
    (git-fixes).

  - ACPI / extlog: Check for RDMSR failure (git-fixes).

  - ACPI: video: use ACPI backlight for HP 635 Notebook
    (git-fixes).

  - act_ife: load meta modules before tcf_idr_check_alloc()
    (networking-stable-20_09_24).

  - Add CONFIG_CHECK_CODESIGN_EKU

  - airo: Fix read overflows sending packets (git-fixes).

  - ALSA: ac97: (cosmetic) align argument names (git-fixes).

  - ALSA: aoa: i2sbus: use DECLARE_COMPLETION_ONSTACK()
    macro (git-fixes).

  - ALSA: asihpi: fix spellint typo in comments (git-fixes).

  - ALSA: atmel: ac97: clarify operator precedence
    (git-fixes).

  - ALSA: bebob: potential info leak in hwdep_read()
    (git-fixes).

  - ALSA: compress_offload: remove redundant initialization
    (git-fixes).

  - ALSA: core: init: use DECLARE_COMPLETION_ONSTACK() macro
    (git-fixes).

  - ALSA: core: pcm: simplify locking for timers
    (git-fixes).

  - ALSA: core: timer: clarify operator precedence
    (git-fixes).

  - ALSA: core: timer: remove redundant assignment
    (git-fixes).

  - ALSA: ctl: Workaround for lockdep warning wrt
    card->ctl_files_rwlock (git-fixes).

  - ALSA: fireworks: use semicolons rather than commas to
    separate statements (git-fixes).

  - ALSA: fix kernel-doc markups (git-fixes).

  - ALSA: hda: auto_parser: remove shadowed variable
    declaration (git-fixes).

  - ALSA: hda: (cosmetic) align function parameters
    (git-fixes).

  - ALSA: hda - Do not register a cb func if it is
    registered already (git-fixes).

  - ALSA: hda - Fix the return value if cb func is already
    registered (git-fixes).

  - ALSA: hda/hdmi: fix incorrect locking in hdmi_pcm_close
    (git-fixes).

  - ALSA: hda: prevent undefined shift in
    snd_hdac_ext_bus_get_link() (git-fixes).

  - ALSA: hda/realtek - Add mute Led support for HP
    Elitebook 845 G7 (git-fixes).

  - ALSA: hda/realtek: Enable audio jacks of ASUS D700SA
    with ALC887 (git-fixes).

  - ALSA: hda/realtek - Enable headphone for ASUS TM420
    (git-fixes).

  - ALSA: hda/realtek - Fixed HP headset Mic can't be
    detected (git-fixes).

  - ALSA: hda/realtek - set mic to auto detect on a HP AIO
    machine (git-fixes).

  - ALSA: hda/realtek - The front Mic on a HP machine does
    not work (git-fixes).

  - ALSA: hda: use semicolons rather than commas to separate
    statements (git-fixes).

  - ALSA: hdspm: Fix typo arbitary (git-fixes).

  - ALSA: mixart: Correct comment wrt obsoleted tasklet
    usage (git-fixes).

  - ALSA: portman2x4: fix repeated word 'if' (git-fixes).

  - ALSA: rawmidi: (cosmetic) align function parameters
    (git-fixes).

  - ALSA: seq: oss: Avoid mutex lock for a long-time ioctl
    (git-fixes).

  - ALSA: sparc: dbri: fix repeated word 'the' (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for MODX
    (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for Qu-16
    (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for Zoom
    UAC-2 (git-fixes).

  - ALSA: usb-audio: Add mixer support for Pioneer DJ
    DJM-250MK2 (git-fixes).

  - ALSA: usb-audio: add usb vendor id as DSD-capable for
    Khadas devices (git-fixes).

  - ALSA: usb-audio: endpoint.c: fix repeated word 'there'
    (git-fixes).

  - ALSA: usb-audio: fix spelling mistake 'Frequence' ->
    'Frequency' (git-fixes).

  - ALSA: usb-audio: Line6 Pod Go interface requires static
    clock rate quirk (git-fixes).

  - ALSA: usb: scarless_gen2: fix endianness issue
    (git-fixes).

  - ALSA: vx: vx_core: clarify operator precedence
    (git-fixes).

  - ALSA: vx: vx_pcm: remove redundant assignment
    (git-fixes).

  - ar5523: Add USB ID of SMCWUSBT-G2 wireless adapter
    (git-fixes).

  - arm64: Enable PCI write-combine resources under sysfs
    (bsc#1175807).

  - ASoC: codecs: wcd9335: Set digital gain range correctly
    (git-fixes).

  - ASoC: cs42l51: manage mclk shutdown delay (git-fixes).

  - ASoC: fsl: imx-es8328: add missing put_device() call in
    imx_es8328_probe() (git-fixes).

  - ASoC: fsl_sai: Instantiate snd_soc_dai_driver
    (git-fixes).

  - ASoC: img-i2s-out: Fix runtime PM imbalance on error
    (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for MPMAN
    Converter9 2-in-1 (git-fixes).

  - ASoC: Intel: kbl_rt5663_max98927: Fix kabylake_ssp_fixup
    function (git-fixes).

  - ASoC: kirkwood: fix IRQ error handling (git-fixes).

  - ASoC: qcom: lpass-cpu: fix concurrency issue
    (git-fixes).

  - ASoC: qcom: lpass-platform: fix memory leak (git-fixes).

  - ASoC: qcom: sdm845: set driver name correctly
    (git-fixes).

  - ASoC: sun50i-codec-analog: Fix duplicate use of ADC
    enable bits (git-fixes).

  - ASoC: tlv320aic32x4: Fix bdiv clock rate derivation
    (git-fixes).

  - ASoC: wm8994: Ensure the device is resumed in
    wm89xx_mic_detect functions (git-fixes).

  - ASoC: wm8994: Skip setting of the WM8994_MICBIAS
    register for WM1811 (git-fixes).

  - ata: ahci: mvebu: Make SATA PHY optional for Armada 3720
    (git-fixes).

  - ata: sata_rcar: Fix DMA boundary mask (git-fixes).

  - ath10k: check idx validity in
    __ath10k_htt_rx_ring_fill_n() (git-fixes).

  - ath10k: fix array out-of-bounds access (git-fixes).

  - ath10k: fix memory leak for tpc_stats_final (git-fixes).

  - ath10k: Fix the size used in a 'dma_free_coherent()'
    call in an error handling path (git-fixes).

  - ath10k: fix VHT NSS calculation when STBC is enabled
    (git-fixes).

  - ath10k: provide survey info as accumulated data
    (git-fixes).

  - ath10k: start recovery process when payload length
    exceeds max htc length for sdio (git-fixes).

  - ath10k: use kzalloc to read for
    ath10k_sdio_hif_diag_read (git-fixes).

  - ath6kl: prevent potential array overflow in
    ath6kl_add_new_sta() (git-fixes).

  - ath6kl: wmi: prevent a shift wrapping bug in
    ath6kl_wmi_delete_pstream_cmd() (git-fixes).

  - ath9k: Fix potential out of bounds in
    ath9k_htc_txcompletion_cb() (git-fixes).

  - ath9k: hif_usb: fix race condition between usb_get_urb()
    and usb_kill_anchored_urbs() (git-fixes).

  - ath9k_htc: Use appropriate rs_datalen type (git-fixes).

  - backlight: sky81452-backlight: Fix refcount imbalance on
    error (git-fixes).

  - blk-mq: order adding requests to hctx->dispatch and
    checking SCHED_RESTART (bsc#1177750).

  - block: ensure bdi->io_pages is always initialized
    (bsc#1177749).

  - block: Fix page_is_mergeable() for compound pages
    (bsc#1177814).

  - block: Set same_page to false in __bio_try_merge_page if
    ret is false (git-fixes).

  - Bluetooth: btusb: Fix memleak in
    btusb_mtk_submit_wmt_recv_urb (git-fixes).

  - Bluetooth: Fix refcount use-after-free issue
    (git-fixes).

  - Bluetooth: guard against controllers sending zero'd
    events (git-fixes).

  - Bluetooth: Handle Inquiry Cancel error after Inquiry
    Complete (git-fixes).

  - Bluetooth: hci_uart: Cancel init work before
    unregistering (git-fixes).

  - Bluetooth: L2CAP: handle l2cap config request during
    open state (git-fixes).

  - Bluetooth: MGMT: Fix not checking if BT_HS is enabled
    (git-fixes).

  - Bluetooth: Only mark socket zapped after unlocking
    (git-fixes).

  - Bluetooth: prefetch channel before killing sock
    (git-fixes).

  - bnxt_en: Protect bnxt_set_eee() and
    bnxt_set_pauseparam() with mutex (git-fixes).

  - bonding: show saner speed for broadcast mode
    (networking-stable-20_08_24).

  - brcm80211: fix possible memleak in
    brcmf_proto_msgbuf_attach (git-fixes).

  - brcmfmac: check ndev pointer (git-fixes).

  - brcmfmac: Fix double freeing in the fmac usb data path
    (git-fixes).

  - brcmsmac: fix memory leak in wlc_phy_attach_lcnphy
    (git-fixes).

  - btrfs: Account for merged patches upstream Move below
    patches to sorted section.

  - btrfs: add owner and fs_info to alloc_state io_tree
    (bsc#1177854).

  - btrfs: allocate scrub workqueues outside of locks
    (bsc#1178183).

  - btrfs: block-group: do not set the wrong READA flag for
    btrfs_read_block_groups() (bsc#1176019).

  - btrfs: block-group: fix free-space bitmap threshold
    (bsc#1176019).

  - btrfs: block-group: refactor how we delete one block
    group item (bsc#1176019).

  - btrfs: block-group: refactor how we insert a block group
    item (bsc#1176019).

  - btrfs: block-group: refactor how we read one block group
    item (bsc#1176019).

  - btrfs: block-group: rename write_one_cache_group()
    (bsc#1176019).

  - btrfs: check the right error variable in
    btrfs_del_dir_entries_in_log (bsc#1177687).

  - btrfs: cleanup cow block on error (bsc#1178584).

  - btrfs: do not force read-only after error in drop
    snapshot (bsc#1176354).

  - btrfs: do not set the full sync flag on the inode during
    page release (bsc#1177687).

  - btrfs: do not take an extra root ref at allocation time
    (bsc#1176019).

  - btrfs: drop logs when we've aborted a transaction
    (bsc#1176019).

  - btrfs: drop path before adding new uuid tree entry
    (bsc#1178176).

  - btrfs: fix a race between scrub and block group
    removal/allocation (bsc#1176019).

  - Btrfs: fix crash during unmount due to race with delayed
    inode workers (bsc#1176019).

  - btrfs: fix filesystem corruption after a device replace
    (bsc#1178395).

  - btrfs: fix NULL pointer dereference after failure to
    create snapshot (bsc#1178190).

  - btrfs: fix overflow when copying corrupt csums for a
    message (bsc#1178191).

  - btrfs: fix race between page release and a fast fsync
    (bsc#1177687).

  - btrfs: fix space cache memory leak after transaction
    abort (bsc#1178173).

  - btrfs: free block groups after free'ing fs trees
    (bsc#1176019).

  - btrfs: hold a ref on the root on the dead roots list
    (bsc#1176019).

  - btrfs: kill the subvol_srcu (bsc#1176019).

  - btrfs: make btrfs_cleanup_fs_roots use the radix tree
    lock (bsc#1176019).

  - btrfs: make inodes hold a ref on their roots
    (bsc#1176019).

  - btrfs: make the extent buffer leak check per fs info
    (bsc#1176019).

  - btrfs: move btrfs_rm_dev_replace_free_srcdev outside of
    all locks (bsc#1178395).

  - btrfs: move btrfs_scratch_superblocks into
    btrfs_dev_replace_finishing (bsc#1178395).

  - btrfs: move ino_cache_inode dropping out of
    btrfs_free_fs_root (bsc#1176019).

  - btrfs: move the block group freeze/unfreeze helpers into
    block-group.c (bsc#1176019).

  - btrfs: move the root freeing stuff into btrfs_put_root
    (bsc#1176019).

  - btrfs: only commit delayed items at fsync if we are
    logging a directory (bsc#1177687).

  - btrfs: only commit the delayed inode when doing a full
    fsync (bsc#1177687).

  - btrfs: qgroup: fix qgroup meta rsv leak for subvolume
    operations (bsc#1177856).

  - btrfs: qgroup: fix wrong qgroup metadata reserve for
    delayed inode (bsc#1177855).

  - btrfs: reduce contention on log trees when logging
    checksums (bsc#1177687).

  - btrfs: release old extent maps during page release
    (bsc#1177687).

  - btrfs: remove no longer necessary chunk mutex locking
    cases (bsc#1176019).

  - btrfs: remove no longer needed use of log_writers for
    the log root tree (bsc#1177687).

  - btrfs: rename member 'trimming' of block group to a more
    generic name (bsc#1176019).

  - btrfs: reschedule if necessary when logging directory
    items (bsc#1178585).

  - btrfs: scrub, only lookup for csums if we are dealing
    with a data extent (bsc#1176019).

  - btrfs: send, orphanize first all conflicting inodes when
    processing references (bsc#1178579).

  - btrfs: send, recompute reference path after
    orphanization of a directory (bsc#1178581).

  - btrfs: set the correct lockdep class for new nodes
    (bsc#1178184).

  - btrfs: set the lockdep class for log tree extent buffers
    (bsc#1178186).

  - btrfs: stop incremening log_batch for the log root tree
    when syncing log (bsc#1177687).

  - btrfs: tree-checker: fix false alert caused by legacy
    btrfs root item (bsc#1177861).

  - bus: hisi_lpc: Fixup IO ports addresses to avoid
    use-after-free in host removal (git-fixes).

  - can: can_create_echo_skb(): fix echo skb generation:
    always use skb_clone() (git-fixes).

  - can: c_can: reg_map_(c,d)_can: mark as __maybe_unused
    (git-fixes).

  - can: dev: __can_get_echo_skb(): fix real payload length
    return value for RTR frames (git-fixes).

  - can: dev: can_get_echo_skb(): prevent call to
    kfree_skb() in hard IRQ context (git-fixes).

  - can: flexcan: flexcan_chip_stop(): add error handling
    and propagate error value (git-fixes).

  - can: flexcan: flexcan_remove(): disable wakeup
    completely (git-fixes).

  - can: flexcan: remove ack_grp and ack_bit handling from
    driver (git-fixes).

  - can: flexcan: remove FLEXCAN_QUIRK_DISABLE_MECR quirk
    for LS1021A (git-fixes).

  - can: peak_canfd: pucan_handle_can_rx(): fix echo
    management when loopback is on (git-fixes).

  - can: peak_usb: add range checking in decode operations
    (git-fixes).

  - can: peak_usb: peak_usb_get_ts_time(): fix timestamp
    wrapping (git-fixes).

  - can: rx-offload: do not call kfree_skb() from IRQ
    context (git-fixes).

  - can: softing: softing_card_shutdown(): add braces around
    empty body in an 'if' statement (git-fixes).

  - ceph: promote to unsigned long long before shifting
    (bsc#1178175).

  - clk: at91: clk-main: update key before writing
    AT91_CKGR_MOR (git-fixes).

  - clk: at91: remove the checking of parent_name
    (git-fixes).

  - clk: bcm2835: add missing release if
    devm_clk_hw_register fails (git-fixes).

  - clk: imx8mq: Fix usdhc parents order (git-fixes).

  - clk: keystone: sci-clk: fix parsing assigned-clock data
    during probe (git-fixes).

  - clk: meson: g12a: mark fclk_div2 as critical
    (git-fixes).

  - clk: qcom: gcc-sdm660: Fix wrong parent_map (git-fixes).

  - clk: samsung: exynos4: mark 'chipid' clock as
    CLK_IGNORE_UNUSED (git-fixes).

  - clk: socfpga: stratix10: fix the divider for the
    emac_ptp_free_clk (git-fixes).

  - clk: tegra: Always program PLL_E when enabled
    (git-fixes).

  - clk/ti/adpll: allocate room for terminating null
    (git-fixes).

  - clocksource/drivers/h8300_timer8: Fix wrong return value
    in h8300_8timer_init() (git-fixes).

  - clocksource/drivers/timer-gx6605s: Fixup counter reload
    (git-fixes).

  - cpuidle: Poll for a minimum of 30ns and poll for a tick
    if lower c-states are disabled (bnc#1176588).

  - create Storage / NVMe subsection

  - crypto: algif_aead - Do not set MAY_BACKLOG on the async
    path (git-fixes).

  - crypto: algif_skcipher - EBUSY on aio should be an error
    (git-fixes).

  - crypto: bcm - Verify GCM/CCM key length in setkey
    (git-fixes).

  - crypto: ccp - fix error handling (git-fixes).

  - crypto: dh - check validity of Z before export
    (bsc#1175718).

  - crypto: dh - SP800-56A rev 3 local public key validation
    (bsc#1175718).

  - crypto: ecc - SP800-56A rev 3 local public key
    validation (bsc#1175718).

  - crypto: ecdh - check validity of Z before export
    (bsc#1175718).

  - crypto: ixp4xx - Fix the size used in a
    'dma_free_coherent()' call (git-fixes).

  - crypto: mediatek - Fix wrong return value in
    mtk_desc_ring_alloc() (git-fixes).

  - crypto: omap-sham - fix digcnt register handling with
    export/import (git-fixes).

  - crypto: picoxcell - Fix potential race condition bug
    (git-fixes).

  - crypto: qat - check cipher length for aead
    AES-CBC-HMAC-SHA (git-fixes).

  - cxgb4: fix memory leak during module unload
    (networking-stable-20_09_24).

  - cxgb4: Fix offset when clearing filter byte counters
    (networking-stable-20_09_24).

  - cxl: Rework error message for incompatible slots
    (bsc#1055014 git-fixes).

  - cypto: mediatek - fix leaks in mtk_desc_ring_alloc
    (git-fixes).

  - dax: Fix compilation for CONFIG_DAX && !CONFIG_FS_DAX
    (bsc#1177817).

  - Disable module compression on SLE15 SP2 (bsc#1178307)

  - dma-direct: add missing set_memory_decrypted() for
    coherent mapping (bsc#1175898, ECO-2743).

  - dma-direct: always align allocation size in
    dma_direct_alloc_pages() (bsc#1175898, ECO-2743).

  - dma-direct: atomic allocations must come from atomic
    coherent pools (bsc#1175898, ECO-2743).

  - dma-direct: check return value when encrypting or
    decrypting memory (bsc#1175898, ECO-2743).

  - dma-direct: consolidate the error handling in
    dma_direct_alloc_pages (bsc#1175898, ECO-2743).

  - dma-direct: make uncached_kernel_address more general
    (bsc#1175898, ECO-2743).

  - dma-direct: provide function to check physical memory
    area validity (bsc#1175898, ECO-2743).

  - dma-direct: provide mmap and get_sgtable method
    overrides (bsc#1175898, ECO-2743).

  - dma-direct: re-encrypt memory if
    dma_direct_alloc_pages() fails (bsc#1175898, ECO-2743).

  - dma-direct: remove __dma_direct_free_pages (bsc#1175898,
    ECO-2743).

  - dma-direct: remove the dma_handle argument to
    __dma_direct_alloc_pages (bsc#1175898, ECO-2743).

  - dmaengine: dma-jz4780: Fix race in jz4780_dma_tx_status
    (git-fixes).

  - dmaengine: dmatest: Check list for emptiness before
    access its last entry (git-fixes).

  - dmaengine: dw: Activate FIFO-mode for memory peripherals
    only (git-fixes).

  - dmaengine: mediatek: hsdma_probe: fixed a memory leak
    when devm_request_irq fails (git-fixes).

  - dmaengine: stm32-dma: use vchan_terminate_vdesc() in
    .terminate_all (git-fixes).

  - dmaengine: stm32-mdma: use vchan_terminate_vdesc() in
    .terminate_all (git-fixes).

  - dmaengine: tegra-apb: Prevent race conditions on
    channel's freeing (git-fixes).

  - dmaengine: zynqmp_dma: fix burst length configuration
    (git-fixes).

  - dma-fence: Serialise signal enabling
    (dma_fence_enable_sw_signaling) (git-fixes).

  - dma-mapping: add a dma_can_mmap helper (bsc#1175898,
    ECO-2743).

  - dma-mapping: always use VM_DMA_COHERENT for generic DMA
    remap (bsc#1175898, ECO-2743).

  - dma-mapping: DMA_COHERENT_POOL should select
    GENERIC_ALLOCATOR (bsc#1175898, ECO-2743).

  - dma-mapping: make dma_atomic_pool_init self-contained
    (bsc#1175898, ECO-2743).

  - dma-mapping: merge the generic remapping helpers into
    dma-direct (bsc#1175898, ECO-2743).

  - dma-mapping: remove arch_dma_mmap_pgprot (bsc#1175898,
    ECO-2743).

  - dma-mapping: warn when coherent pool is depleted
    (bsc#1175898, ECO-2743).

  - dma-pool: add additional coherent pools to map to gfp
    mask (bsc#1175898, ECO-2743).

  - dma-pool: add pool sizes to debugfs (bsc#1175898,
    ECO-2743).

  - dma-pool: decouple DMA_REMAP from DMA_COHERENT_POOL
    (bsc#1175898, ECO-2743).

  - dma-pool: do not allocate pool memory from CMA
    (bsc#1175898, ECO-2743).

  - dma-pool: dynamically expanding atomic pools
    (bsc#1175898, ECO-2743).

  - dma-pool: Fix an uninitialized variable bug in
    atomic_pool_expand() (bsc#1175898, ECO-2743).

  - dma-pool: fix coherent pool allocations for IOMMU
    mappings (bsc#1175898, ECO-2743).

  - dma-pool: fix too large DMA pools on medium memory size
    systems (bsc#1175898, ECO-2743).

  - dma-pool: get rid of dma_in_atomic_pool() (bsc#1175898,
    ECO-2743).

  - dma-pool: introduce dma_guess_pool() (bsc#1175898,
    ECO-2743).

  - dma-pool: make sure atomic pool suits device
    (bsc#1175898, ECO-2743).

  - dma-pool: Only allocate from CMA when in same memory
    zone (bsc#1175898, ECO-2743).

  - dma-pool: scale the default DMA coherent pool size with
    memory capacity (bsc#1175898, ECO-2743).

  - dma-remap: separate DMA atomic pools from direct remap
    code (bsc#1175898, ECO-2743).

  - dm: Call proper helper to determine dax support
    (bsc#1177817).

  - dm/dax: Fix table reference counts (bsc#1178246).

  - docs: driver-api: remove a duplicated index entry
    (git-fixes).

  - drivers: char: tlclk.c: Avoid data race between init and
    interrupt handler (git-fixes).

  - drivers: watchdog: rdc321x_wdt: Fix race condition bugs
    (git-fixes).

  - drm/amdgpu: restore proper ref count in
    amdgpu_display_crtc_set_config (git-fixes).

  - drm/radeon: revert 'Prefer lower feedback dividers'
    (bsc#1177384).

  - drop Storage / bsc#1171688 subsection No effect on
    expanded tree.

  - e1000: Do not perform reset in reset_task if we are
    already down (git-fixes).

  - EDAC/i5100: Fix error handling order in i5100_init_one()
    (bsc#1152489).

  - eeprom: at25: set minimum read/write access stride to 1
    (git-fixes).

  - exfat: fix name_hash computation on big endian systems
    (git-fixes).

  - exfat: fix overflow issue in exfat_cluster_to_sector()
    (git-fixes).

  - exfat: fix possible memory leak in exfat_find()
    (git-fixes).

  - exfat: fix use of uninitialized spinlock on error path
    (git-fixes).

  - exfat: fix wrong hint_stat initialization in
    exfat_find_dir_entry() (git-fixes).

  - exfat: fix wrong size update of stream entry by typo
    (git-fixes).

  - extcon: ptn5150: Fix usage of atomic GPIO with sleeping
    GPIO chips (git-fixes).

  - ftrace: Move RCU is watching check after recursion check
    (git-fixes).

  - fuse: do not ignore errors from fuse_writepages_fill()
    (bsc#1177193).

  - futex: Adjust absolute futex timeouts with per time
    namespace offset (bsc#1164648).

  - futex: Consistently use fshared as boolean
    (bsc#1149032).

  - futex: Fix incorrect should_fail_futex() handling
    (bsc#1149032).

  - futex: Remove put_futex_key() (bsc#1149032).

  - futex: Remove unused or redundant includes
    (bsc#1149032).

  - gpio: mockup: fix resource leak in error path
    (git-fixes).

  - gpio: rcar: Fix runtime PM imbalance on error
    (git-fixes).

  - gpio: siox: explicitly support only threaded irqs
    (git-fixes).

  - gpio: sprd: Clear interrupt when setting the type as
    edge (git-fixes).

  - gpio: tc35894: fix up tc35894 interrupt configuration
    (git-fixes).

  - gre6: Fix reception with IP6_TNL_F_RCV_DSCP_COPY
    (networking-stable-20_08_24).

  - gtp: add GTPA_LINK info to msg sent to userspace
    (networking-stable-20_09_11).

  - HID: hid-input: fix stylus battery reporting
    (git-fixes).

  - HID: ite: Add USB id match for Acer One S1003 keyboard
    dock (git-fixes).

  - HID: roccat: add bounds checking in
    kone_sysfs_write_settings() (git-fixes).

  - HID: wacom: Avoid entering wacom_wac_pen_report for pad
    / battery (git-fixes).

  - hwmon: (applesmc) check status earlier (git-fixes).

  - hwmon: (mlxreg-fan) Fix double 'Mellanox' (git-fixes).

  - hwmon: (pmbus/max34440) Fix status register reads for
    MAX344(51,60,61) (git-fixes).

  - hyperv_fb: Update screen_info after removing old
    framebuffer (bsc#1175306).

  - i2c: aspeed: Mask IRQ status to relevant bits
    (git-fixes).

  - i2c: core: Call i2c_acpi_install_space_handler() before
    i2c_acpi_register_devices() (git-fixes).

  - i2c: core: Restore acpi_walk_dep_device_list() getting
    called after registering the ACPI i2c devs (git-fixes).

  - i2c: cpm: Fix i2c_ram structure (git-fixes).

  - i2c: i801: Exclude device from suspend direct complete
    optimization (git-fixes).

  - i2c: imx: Fix external abort on interrupt in exit paths
    (git-fixes).

  - i2c: meson: fix clock setting overwrite (git-fixes).

  - i2c: meson: fixup rate calculation with filter delay
    (git-fixes).

  - i2c: owl: Clear NACK and BUS error bits (git-fixes).

  - i2c: rcar: Auto select RESET_CONTROLLER (git-fixes).

  - i2c: tegra: Prevent interrupt triggering after transfer
    timeout (git-fixes).

  - i2c: tegra: Restore pinmux on system resume (git-fixes).

  - i3c: master add i3c_master_attach_boardinfo to preserve
    boardinfo (git-fixes).

  - i3c: master: Fix error return in cdns_i3c_master_probe()
    (git-fixes).

  - ibmveth: Identify ingress large send packets
    (bsc#1178185 ltc#188897).

  - ibmveth: Switch order of ibmveth_helper calls
    (bsc#1061843 git-fixes).

  - ibmvnic: fix ibmvnic_set_mac (bsc#1066382 ltc#160943
    git-fixes).

  - ibmvnic: save changed mac address to adapter->mac_addr
    (bsc#1134760 ltc#177449 git-fixes).

  - ibmvnic: set up 200GBPS speed (bsc#1129923 git-fixes).

  - icmp: randomize the global rate limiter (git-fixes).

  - ida: Free allocated bitmap in error path (git-fixes).

  - ieee802154/adf7242: check status of adf7242_read_reg
    (git-fixes).

  - ieee802154: fix one possible memleak in
    ca8210_dev_com_init (git-fixes).

  - iio:accel:bma180: Fix use of true when should be
    iio_shared_by enum (git-fixes).

  - iio: adc: gyroadc: fix leak of device node iterator
    (git-fixes).

  - iio: adc: qcom-spmi-adc5: fix driver name (git-fixes).

  - iio: adc: stm32-adc: fix runtime autosuspend delay when
    slow polling (git-fixes).

  - iio:adc:ti-adc0832 Fix alignment issue with timestamp
    (git-fixes).

  - iio:adc:ti-adc12138 Fix alignment issue with timestamp
    (git-fixes).

  - iio:dac:ad5592r: Fix use of true for IIO_SHARED_BY_TYPE
    (git-fixes).

  - iio:gyro:itg3200: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:light:si1145: Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:magn:hmc5843: Fix passing true where iio_shared_by
    enum required (git-fixes).

  - ima: Do not ignore errors from crypto_shash_update()
    (git-fixes).

  - ima: extend boot_aggregate with kernel measurements
    (bsc#1177617).

  - ima: Remove semicolon at the end of
    ima_get_binary_runtime_size() (git-fixes).

  - Input: ati_remote2 - add missing newlines when printing
    module parameters (git-fixes).

  - Input: ep93xx_keypad - fix handling of
    platform_get_irq() error (git-fixes).

  - Input: i8042 - add nopnp quirk for Acer Aspire 5 A515
    (bsc#954532).

  - Input: imx6ul_tsc - clean up some errors in
    imx6ul_tsc_resume() (git-fixes).

  - Input: omap4-keypad - fix handling of platform_get_irq()
    error (git-fixes).

  - Input: stmfts - fix a & vs && typo (git-fixes).

  - Input: sun4i-ps2 - fix handling of platform_get_irq()
    error (git-fixes).

  - Input: trackpoint - enable Synaptics trackpoints
    (git-fixes).

  - Input: twl4030_keypad - fix handling of
    platform_get_irq() error (git-fixes).

  - iomap: Make sure iomap_end is called after iomap_begin
    (bsc#1177754).

  - iommu/amd: Fix IOMMU AVIC not properly update the is_run
    bit in IRTE (bsc#1177297).

  - iommu/amd: Fix potential @entry null deref
    (bsc#1177283).

  - iommu/amd: Re-factor guest virtual APIC (de-)activation
    code (bsc#1177284).

  - iommu/amd: Restore IRTE.RemapEn bit for
    amd_iommu_activate_guest_mode (bsc#1177285).

  - iommu/exynos: add missing put_device() call in
    exynos_iommu_of_xlate() (bsc#1177286).

  - iommu/vt-d: Correctly calculate agaw in domain_init()
    (bsc#1176400).

  - iommu/vt-d: Gracefully handle DMAR units with no
    supported address widths (bsc#1177739).

  - ip: fix tos reflection in ack and reset packets
    (networking-stable-20_09_24).

  - ipmi_si: Fix wrong return value in try_smi_init()
    (git-fixes).

  - ipv4: Initialize flowi4_multipath_hash in data path
    (networking-stable-20_09_24).

  - ipv4: Restore flowi4_oif update before call to
    xfrm_lookup_route (git-fixes).

  - ipv4: Update exception handling for multipath routes via
    same device (networking-stable-20_09_24).

  - ipv6: avoid lockdep issue in fib6_del()
    (networking-stable-20_09_24).

  - ipv6: Fix sysctl max for fib_multipath_hash_policy
    (networking-stable-20_09_11).

  - ipvlan: fix device features
    (networking-stable-20_08_24).

  - iwlwifi: mvm: split a print to avoid a WARNING in ROC
    (git-fixes).

  - kabi fix for NFS: Fix flexfiles read failover
    (git-fixes).

  - kABI: Fix kABI after add CodeSigning extended key usage
    (bsc#1177353).

  - kABI: Fix kABI for 12856e7acde4 PCI/IOV: Mark VFs as not
    implementing PCI_COMMAND_MEMORY (bsc#1176979).

  - kabi/severities: ignore kABI for target_core_rbd Match
    behaviour for all other Ceph specific modules.

  - kallsyms: Refactor kallsyms_show_value() to take cred
    (git-fixes).

  - kbuild: enforce -Werror=return-type (bsc#1177281).

  - kernel-binary.spec.in: Exclude .config.old from
    kernel-devel - use tar excludes for
    .kernel-binary.spec.buildenv

  - kernel-binary.spec.in: Package the obj_install_dir as
    explicit filelist.

  - KVM: x86/mmu: Commit zap of remaining invalid pages when
    recovering lpages (git-fixes).

  - leds: bcm6328, bcm6358: use devres LED registering
    function (git-fixes).

  - leds: mlxreg: Fix possible buffer overflow (git-fixes).

  - leds: mt6323: move period calculation (git-fixes).

  -
    libceph-add-support-for-CMPEXT-compare-extent-reques.pat
    ch: (bsc#1177090).

  - libceph: clear con->out_msg on Policy::stateful_server
    faults (bsc#1178177).

  - lib/crc32.c: fix trivial typo in preprocessor condition
    (git-fixes).

  - lib/mpi: Add mpi_sub_ui() (bsc#1175718).

  - locking/rwsem: Disable reader optimistic spinning
    (bnc#1176588).

  - mac80211: do not allow bigger VHT MPDUs than the
    hardware supports (git-fixes).

  - mac80211: handle lack of sband->bitrates in rates
    (git-fixes).

  - mac80211: skip mpath lookup also for control port tx
    (git-fixes).

  - mac802154: tx: fix use-after-free (git-fixes).

  - macsec: avoid use-after-free in macsec_handle_frame()
    (git-fixes).

  - mailbox: avoid timer start from callback (git-fixes).

  - media: ati_remote: sanity check for both endpoints
    (git-fixes).

  - media: bdisp: Fix runtime PM imbalance on error
    (git-fixes).

  - media: camss: Fix a reference count leak (git-fixes).

  - media: exynos4-is: Fix a reference count leak due to
    pm_runtime_get_sync (git-fixes).

  - media: exynos4-is: Fix a reference count leak
    (git-fixes).

  - media: exynos4-is: Fix several reference count leaks due
    to pm_runtime_get_sync (git-fixes).

  - media: firewire: fix memory leak (git-fixes).

  - media: i2c: ov5640: Enable data pins on poweron for DVP
    mode (git-fixes).

  - media: i2c: ov5640: Remain in power down for DVP mode
    unless streaming (git-fixes).

  - media: i2c: ov5640: Separate out mipi configuration from
    s_power (git-fixes).

  - media: imx274: fix frame interval handling (git-fixes).

  - media: m5mols: Check function pointer in
    m5mols_sensor_power (git-fixes).

  - media: mc-device.c: fix memleak in
    media_device_register_entity (git-fixes).

  - media: media/pci: prevent memory leak in bttv_probe
    (git-fixes).

  - media: mx2_emmaprp: Fix memleak in emmaprp_probe
    (git-fixes).

  - media: omap3isp: Fix memleak in isp_probe (git-fixes).

  - media: ov5640: Correct Bit Div register in clock tree
    diagram (git-fixes).

  - media: platform: fcp: Fix a reference count leak
    (git-fixes).

  - media: platform: Improve queue set up flow for bug
    fixing (git-fixes).

  - media: platform: s3c-camif: Fix runtime PM imbalance on
    error (git-fixes).

  - media: platform: sti: hva: Fix runtime PM imbalance on
    error (git-fixes).

  - media: rcar-csi2: Allocate v4l2_async_subdev dynamically
    (git-fixes).

  - media: rcar_drif: Allocate v4l2_async_subdev dynamically
    (git-fixes).

  - media: rcar_drif: Fix fwnode reference leak when parsing
    DT (git-fixes).

  - media: rcar-vin: Fix a reference count leak (git-fixes).

  - media: rc: do not access device via sysfs after
    rc_unregister_device() (git-fixes).

  - media: rc: uevent sysfs file races with
    rc_unregister_device() (git-fixes).

  - media: Revert 'media: exynos4-is: Add missed check for
    pinctrl_lookup_state()' (git-fixes).

  - media: rockchip/rga: Fix a reference count leak
    (git-fixes).

  - media: s5p-mfc: Fix a reference count leak (git-fixes).

  - media: saa7134: avoid a shift overflow (git-fixes).

  - media: smiapp: Fix error handling at NVM reading
    (git-fixes).

  - media: staging/intel-ipu3: css: Correctly reset some
    memory (git-fixes).

  - media: st-delta: Fix reference count leak in
    delta_run_work (git-fixes).

  - media: sti: Fix reference count leaks (git-fixes).

  - media: stm32-dcmi: Fix a reference count leak
    (git-fixes).

  - media: tc358743: cleanup tc358743_cec_isr (git-fixes).

  - media: tc358743: initialize variable (git-fixes).

  - media: ti-vpe: cal: Restrict DMA to avoid memory
    corruption (git-fixes).

  - media: ti-vpe: Fix a missing check and reference count
    leak (git-fixes).

  - media: tuner-simple: fix regression in
    simple_set_radio_freq (git-fixes).

  - media: tw5864: check status of tw5864_frameinterval_get
    (git-fixes).

  - media: usbtv: Fix refcounting mixup (git-fixes).

  - media: uvcvideo: Ensure all probed info is returned to
    v4l2 (git-fixes).

  - media: uvcvideo: Fix dereference of out-of-bound list
    iterator (git-fixes).

  - media: uvcvideo: Fix uvc_ctrl_fixup_xu_info() not having
    any effect (git-fixes).

  - media: uvcvideo: Set media controller entity functions
    (git-fixes).

  - media: uvcvideo: Silence shift-out-of-bounds warning
    (git-fixes).

  - media: v4l2-async: Document asd allocation requirements
    (git-fixes).

  - media: venus: core: Fix runtime PM imbalance in
    venus_probe (git-fixes).

  - media: vsp1: Fix runtime PM imbalance on error
    (git-fixes).

  - memory: fsl-corenet-cf: Fix handling of
    platform_get_irq() error (git-fixes).

  - memory: omap-gpmc: Fix a couple off by ones (git-fixes).

  - memory: omap-gpmc: Fix build error without CONFIG_OF
    (git-fixes).

  - mfd: mfd-core: Protect against NULL call-back function
    pointer (git-fixes).

  - mfd: sm501: Fix leaks in probe() (git-fixes).

  - mic: vop: copy data to kernel space then write to io
    memory (git-fixes).

  - misc: mic: scif: Fix error handling path (git-fixes).

  - misc: rtsx: Fix memory leak in rtsx_pci_probe
    (git-fixes).

  - misc: vop: add round_up(x,4) for vring_size to avoid
    kernel panic (git-fixes).

  - mm: call cond_resched() from deferred_init_memmap() (git
    fixes (mm/init), bsc#1177697).

  - mmc: core: do not set limits.discard_granularity as 0
    (git-fixes).

  - mmc: core: Rework wp-gpio handling (git-fixes).

  - mm, compaction: fully assume capture is not NULL in
    compact_zone_order() (git fixes (mm/compaction),
    bsc#1177681).

  - mm, compaction: make capture control handling safe wrt
    interrupts (git fixes (mm/compaction), bsc#1177681).

  - mmc: sdhci-acpi: AMDI0040: Set
    SDHCI_QUIRK2_PRESET_VALUE_BROKEN (git-fixes).

  - mmc: sdhci: Add LTR support for some Intel BYT based
    controllers (git-fixes).

  - mmc: sdhci: Workaround broken command queuing on Intel
    GLK based IRBIS models (git-fixes).

  - mmc: sdio: Check for CISTPL_VERS_1 buffer size
    (git-fixes).

  - mm/debug.c: always print flags in dump_page() (git fixes
    (mm/debug)).

  - mm: do not panic when links can't be created in sysfs
    (bsc#1178002).

  - mm: do not rely on system state to detect hot-plug
    operations (bsc#1178002).

  - mm: fix a race during THP splitting (bsc#1178255).

  - mm/huge_memory.c: use head to check huge zero page
    (git-fixes (mm/thp)).

  - mm: initialize deferred pages with interrupts enabled
    (git fixes (mm/init), bsc#1177697).

  - mm: madvise: fix vma user-after-free (git-fixes).

  - mm/memcontrol.c: lost css_put in
    memcg_expand_shrinker_maps() (bsc#1177694).

  - mm/mempolicy.c: fix out of bounds write in
    mpol_parse_str() (git-fixes (mm/mempolicy)).

  - mm/migrate.c: also overwrite error when it is bigger
    than zero (git fixes (mm/move_pages), bsc#1177683).

  - mm: move_pages: report the number of non-attempted pages
    (git fixes (mm/move_pages), bsc#1177683).

  - mm: move_pages: return valid node id in status if the
    page is already on the target node (git fixes
    (mm/move_pages), bsc#1177683).

  - mm/pagealloc.c: call touch_nmi_watchdog() on max order
    boundaries in deferred init (git fixes (mm/init),
    bsc#1177697).

  - mm/page-writeback.c: avoid potential division by zero in
    wb_min_max_ratio() (git-fixes (mm/writeback)).

  - mm/page-writeback.c: improve arithmetic divisions
    (git-fixes (mm/writeback)).

  - mm: replace memmap_context by meminit_context
    (bsc#1178002).

  - mm/rmap: fixup copying of soft dirty and uffd ptes
    (git-fixes (mm/rmap)).

  - mm, slab/slub: improve error reporting and overhead of
    cache_from_obj() (mm/slub bsc#1165692).

  - mm, slab/slub: move and improve cache_from_obj()
    (mm/slub bsc#1165692).

  - mm, slub: extend checks guarded by slub_debug static key
    (mm/slub bsc#1165692).

  - mm, slub: extend slub_debug syntax for multiple blocks
    (mm/slub bsc#1165692).

  - mm, slub: introduce kmem_cache_debug_flags() (mm/slub
    bsc#1165692).

  - mm, slub: introduce static key for slub_debug() (mm/slub
    bsc#1165692).

  - mm, slub: make reclaim_account attribute read-only
    (mm/slub bsc#1165692).

  - mm, slub: make remaining slub_debug related attributes
    read-only (mm/slub bsc#1165692).

  - mm, slub: make some slub_debug related attributes
    read-only (mm/slub bsc#1165692).

  - mm, slub: remove runtime allocation order changes
    (mm/slub bsc#1165692).

  - mm, slub: restore initial kmem_cache flags (mm/slub
    bsc#1165692).

  - mm/swapfile.c: fix potential memory leak in sys_swapon
    (git-fixes).

  - mm/zsmalloc.c: fix the migrated zspage statistics
    (git-fixes (mm/zsmalloc)).

  - module: Correctly truncate sysfs sections output
    (git-fixes).

  - module: Do not expose section addresses to
    non-CAP_SYSLOG (git-fixes).

  - module: Refactor section attr into bin attribute
    (git-fixes).

  - module: statically initialize init section freeing data
    (git-fixes).

  - Move upstreamed BT patch into sorted section

  - Move upstreamed intel-vbtn patch into sorted section

  - mt76: add missing locking around ampdu action
    (git-fixes).

  - mt76: clear skb pointers from rx aggregation reorder
    buffer during cleanup (git-fixes).

  - mt76: do not use devm API for led classdev (git-fixes).

  - mt76: fix handling full tx queues in
    mt76_dma_tx_queue_skb_raw (git-fixes).

  - mt76: fix LED link time failure (git-fixes).

  - mtd: cfi_cmdset_0002: do not free cfi->cfiq in error
    path of cfi_amdstd_setup() (git-fixes).

  - mtd: lpddr: Fix bad logic in print_drs_error
    (git-fixes).

  - mtd: lpddr: fix excessive stack usage with clang
    (git-fixes).

  - mtd: mtdoops: Do not write panic data twice (git-fixes).

  - mtd: rawnand: gpmi: Fix runtime PM imbalance on error
    (git-fixes).

  - mtd: rawnand: omap_elm: Fix runtime PM imbalance on
    error (git-fixes).

  - mtd: rawnand: stm32_fmc2: fix a buffer overflow
    (git-fixes).

  - mtd: rawnand: vf610: disable clk on error handling path
    in probe (git-fixes).

  - mtd: spinand: gigadevice: Add QE Bit (git-fixes).

  - mtd: spinand: gigadevice: Only one dummy byte in QUADIO
    (git-fixes).

  - mwifiex: do not call del_timer_sync() on uninitialized
    timer (git-fixes).

  - mwifiex: Do not use GFP_KERNEL in atomic context
    (git-fixes).

  - mwifiex: fix double free (git-fixes).

  - mwifiex: remove function pointer check (git-fixes).

  - mwifiex: Remove unnecessary braces from
    HostCmd_SET_SEQ_NO_BSS_INFO (git-fixes).

  - net: bridge: br_vlan_get_pvid_rcu() should dereference
    the VLAN group under RCU (networking-stable-20_09_24).

  - net/core: check length before updating Ethertype in
    skb_mpls_(push,pop) (git-fixes).

  - net: DCB: Validate DCB_ATTR_DCB_BUFFER argument
    (networking-stable-20_09_24).

  - net: disable netpoll on fresh napis
    (networking-stable-20_09_11).

  - net: dsa: b53: check for timeout
    (networking-stable-20_08_24).

  - net: dsa: rtl8366: Properly clear member config
    (networking-stable-20_09_24).

  - net: fec: correct the error path for regulator disable
    in probe (networking-stable-20_08_24).

  - net: Fix bridge enslavement failure
    (networking-stable-20_09_24).

  - net: Fix potential wrong skb->protocol in
    skb_vlan_untag() (networking-stable-20_08_24).

  - net: hns: Fix memleak in hns_nic_dev_probe
    (networking-stable-20_09_11).

  - net: ipv6: fix kconfig dependency warning for
    IPV6_SEG6_HMAC (networking-stable-20_09_24).

  - netlabel: fix problems with mapping removal
    (networking-stable-20_09_11).

  - net: lantiq: Disable IRQs only if NAPI gets scheduled
    (networking-stable-20_09_24).

  - net: lantiq: Use napi_complete_done()
    (networking-stable-20_09_24).

  - net: lantiq: use netif_tx_napi_add() for TX NAPI
    (networking-stable-20_09_24).

  - net: lantiq: Wake TX queue again
    (networking-stable-20_09_24).

  - net/mlx5e: Enable adding peer miss rules only if merged
    eswitch is supported (networking-stable-20_09_24).

  - net/mlx5e: TLS, Do not expose FPGA TLS counter if not
    supported (networking-stable-20_09_24).

  - net/mlx5: Fix FTE cleanup (networking-stable-20_09_24).

  - net: mscc: ocelot: fix race condition with TX
    timestamping (bsc#1178461).

  - net: phy: Avoid NPD upon phy_detach() when driver is
    unbound (networking-stable-20_09_24).

  - net: phy: Do not warn in phy_stop() on PHY_DOWN
    (networking-stable-20_09_24).

  - net: phy: realtek: fix rtl8211e rx/tx delay config
    (git-fixes).

  - net: qrtr: fix usage of idr in port assignment to socket
    (networking-stable-20_08_24).

  - net/sched: act_ct: Fix skb double-free in
    tcf_ct_handle_fragments() error flow
    (networking-stable-20_08_24).

  - net: sctp: Fix IPv6 ancestor_size calc in
    sctp_copy_descendant (networking-stable-20_09_24).

  - net: sctp: Fix negotiation of the number of data streams
    (networking-stable-20_08_24).

  - net/smc: Prevent kernel-infoleak in __smc_diag_dump()
    (networking-stable-20_08_24).

  - net: systemport: Fix memleak in bcm_sysport_probe
    (networking-stable-20_09_11).

  - net: usb: dm9601: Add USB ID of Keenetic Plus DSL
    (networking-stable-20_09_11).

  - net: usb: qmi_wwan: add Cellient MPL200 card
    (git-fixes).

  - net: usb: rtl8150: set random MAC address when
    set_ethernet_addr() fails (git-fixes).

  - net: wireless: nl80211: fix out-of-bounds access in
    nl80211_del_key() (git-fixes).

  - nfc: Ensure presence of NFC_ATTR_FIRMWARE_NAME attribute
    in nfc_genl_fw_download() (git-fixes).

  - nfp: use correct define to return NONE fec
    (networking-stable-20_09_24).

  - nfsd4: fix NULL dereference in nfsd/clients display code
    (git-fixes).

  - NFS: Do not move layouts to plh_return_segs list while
    in use (git-fixes).

  - NFS: Do not return layout segments that are in use
    (git-fixes).

  - nfs: ensure correct writeback errors are returned on
    close() (git-fixes).

  - NFS: Fix flexfiles read failover (git-fixes).

  - nfs: Fix security label length not being reset
    (bsc#1176381).

  - nfs: nfs_file_write() should check for writeback errors
    (git-fixes).

  - NFSv4.2: fix client's attribute cache management for
    copy_file_range (git-fixes).

  - nl80211: fix non-split wiphy information (git-fixes).

  - NTB: hw: amd: fix an issue about leak system resources
    (git-fixes).

  - ntb: intel: Fix memleak in intel_ntb_pci_probe
    (git-fixes).

  - nvme-multipath: retry commands for dying queues
    (bsc#1171688).

  - nvme-rdma: fix crash due to incorrect cqe (bsc#1174748).

  - nvme-rdma: fix crash when connect rejected
    (bsc#1174748).

  - overflow: Include header file with SIZE_MAX declaration
    (git-fixes).

  - p54: avoid accessing the data mapped to streaming DMA
    (git-fixes).

  - PCI: aardvark: Check for errors from
    pci_bridge_emul_init() call (git-fixes).

  - PCI/ACPI: Whitelist hotplug ports for D3 if power
    managed by ACPI (git-fixes).

  - PCI: Avoid double hpmemsize MMIO window assignment
    (git-fixes).

  - PCI/IOV: Mark VFs as not implementing PCI_COMMAND_MEMORY
    (bsc#1176979).

  - PCI: tegra194: Fix runtime PM imbalance on error
    (git-fixes).

  - PCI: tegra: Fix runtime PM imbalance on error
    (git-fixes).

  - percpu: fix first chunk size calculation for populated
    bitmap (git-fixes (mm/percpu)).

  - perf/x86/amd: Fix sampling Large Increment per Cycle
    events (bsc#1152489).

  - perf/x86: Fix n_pair for cancelled txn (bsc#1152489).

  - phy: ti: am654: Fix a leak in serdes_am654_probe()
    (git-fixes).

  - pinctrl: bcm: fix kconfig dependency warning when
    !GPIOLIB (git-fixes).

  - pinctrl: mcp23s08: Fix mcp23x17 precious range
    (git-fixes).

  - pinctrl: mcp23s08: Fix mcp23x17_regmap initialiser
    (git-fixes).

  - pinctrl: mvebu: Fix i2c sda definition for 98DX3236
    (git-fixes).

  - PKCS#7: Check codeSigning EKU for kernel module and
    kexec pe verification.

  - PKCS#7: Check codeSigning EKU for kernel module and
    kexec pe verification (bsc#1177353).

  - Platform: OLPC: Fix memleak in olpc_ec_probe
    (git-fixes).

  - platform/x86: fix kconfig dependency warning for
    FUJITSU_LAPTOP (git-fixes).

  - platform/x86: fix kconfig dependency warning for
    LG_LAPTOP (git-fixes).

  - platform/x86: intel_pmc_core: do not create a static
    struct device (git-fixes).

  - platform/x86: intel-vbtn: Switch to an allow-list for
    SW_TABLET_MODE reporting (bsc#1175599).

  - platform/x86: mlx-platform: Remove PSU EEPROM
    configuration (git-fixes).

  - platform/x86: thinkpad_acpi: initialize tp_nvram_state
    variable (git-fixes).

  - platform/x86: thinkpad_acpi: re-initialize ACPI buffer
    size when reuse (git-fixes).

  - PM: hibernate: Batch hibernate and resume IO requests
    (bsc#1178079).

  - PM: hibernate: remove the bogus call to get_gendisk() in
    software_resume() (git-fixes).

  - PM: runtime: Drop runtime PM references to supplier on
    link removal (git-fixes).

  - pNFS/flexfiles: Ensure we initialise the mirror bsizes
    correctly on read (git-fixes).

  - powerpc/book3s64/radix: Make radix_mem_block_size 64bit
    (bsc#1055186 ltc#153436 git-fixes).

  - powerpc/dma: Fix dma_map_ops::get_required_mask
    (bsc#1065729).

  - powerpc: Fix undetected data corruption with P9N DD2.1
    VSX CI load emulation (bsc#1065729).

  - powerpc/hwirq: Remove stale forward irq_chip declaration
    (bsc#1065729).

  - powerpc/icp-hv: Fix missing of_node_put() in success
    path (bsc#1065729).

  - powerpc/irq: Drop forward declaration of struct
    irqaction (bsc#1065729).

  - powerpc/papr_scm: Fix warning triggered by
    perf_stats_show() (bsc#1175052 jsc#SLE-13823 bsc#1174969
    jsc#SLE-12769 git-fixes).

  - powerpc/perf/hv-gpci: Fix starting index value
    (bsc#1065729).

  - powerpc/powernv/dump: Fix race while processing OPAL
    dump (bsc#1065729).

  - powerpc/powernv/elog: Fix race while processing OPAL
    error log event (bsc#1065729).

  - powerpc/pseries: Avoid using addr_to_pfn in real mode
    (jsc#SLE-9246 git-fixes).

  - powerpc/pseries: explicitly reschedule during drmem_lmb
    list traversal (bsc#1077428 ltc#163882 git-fixes).

  - powerpc/pseries: Fix missing of_node_put() in rng_init()
    (bsc#1065729).

  - power: supply: bq27xxx: report 'not charging' on all
    types (git-fixes).

  - power: supply: max17040: Correct voltage reading
    (git-fixes).

  - power: supply: test_power: add missing newlines when
    printing parameters by sysfs (git-fixes).

  - pwm: img: Fix NULL pointer access in probe (git-fixes).

  - pwm: lpss: Add range limit check for the base_unit
    register value (git-fixes).

  - pwm: lpss: Fix off by one error in base_unit math in
    pwm_lpss_prepare() (git-fixes).

  - qla2xxx: Return EBUSY on fcport deletion (bsc#1171688).

  - qtnfmac: fix resource leaks on unsupported iftype error
    return path (git-fixes).

  - r8169: fix data corruption issue on RTL8402
    (bsc#1174098).

  - r8169: fix issue with forced threading in combination
    with shared interrupts (git-fixes).

  - r8169: fix operation under forced interrupt threading
    (git-fixes).

  - rapidio: fix the missed put_device() for
    rio_mport_add_riodev (git-fixes).

  - rbd-add-rbd_img_fill_cmp_and_write_from_bvecs.patch:
    (bsc#1177090).

  - rbd-add-support-for-COMPARE_AND_WRITE-CMPEXT.patch:
    (bsc#1177090).

  - RDMA/hfi1: Correct an interlock issue for TID RDMA WRITE
    request (bsc#1175621).

  - Refresh
    patches.suse/fnic-to-not-call-scsi_done-for-unhandled-co
    mmands.patch (bsc#1168468, bsc#1171675).

  - regulator: axp20x: fix LDO2/4 description (git-fixes).

  - regulator: defer probe when trying to get voltage from
    unresolved supply (git-fixes).

  - regulator: resolve supply after creating regulator
    (git-fixes).

  - rename Other drivers / Intel IOMMU subsection to IOMMU

  - reset: sti: reset-syscfg: fix struct description
    warnings (git-fixes).

  - ring-buffer: Return 0 on success from
    ring_buffer_resize() (git-fixes).

  - rpm/kernel-module-subpackage: make Group tag optional
    (bsc#1163592)

  - rtc: ds1374: fix possible race condition (git-fixes).

  - rtc: rx8010: do not modify the global rtc ops
    (git-fixes).

  - rtc: sa1100: fix possible race condition (git-fixes).

  - rtl8xxxu: prevent potential memory leak (git-fixes).

  - rtw88: increse the size of rx buffer size (git-fixes).

  - s390/cio: add cond_resched() in the slow_eval_known_fn()
    loop (bsc#1177799 LTC#188733).

  - s390/dasd: Fix zero write for FBA devices (bsc#1177801
    LTC#188735).

  - s390/pci: Mark all VFs as not implementing
    PCI_COMMAND_MEMORY (bsc#1176979).

  - sched/fair: Ignore cache hotness for SMT migration
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched/fair: Use dst group while checking imbalance for
    NUMA balancer (bnc#1155798 (CPU scheduler functional and
    performance backports)).

  - sched/numa: Avoid creating large imbalances at task
    creation time (bnc#1176588).

  - sched/numa: Check numa balancing information only when
    enabled (bnc#1176588).

  - sched/numa: Use runnable_avg to classify node
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - scsi: ibmvfc: Fix error return in ibmvfc_probe()
    (bsc#1065729).

  - scsi: ibmvscsi: Fix potential race after loss of
    transport (bsc#1178166 ltc#188226).

  - scsi: iscsi: iscsi_tcp: Avoid holding spinlock while
    calling getpeername() (bsc#1177258).

  - scsi: mptfusion: Do not use GFP_ATOMIC for larger DMA
    allocations (bsc#1175898, ECO-2743).

  - scsi: qla2xxx: Add IOCB resource tracking (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Add rport fields in debugfs (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Add SLER and PI control support
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Allow dev_loss_tmo setting for FC-NVMe
    devices (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Correct the check for sscanf() return
    value (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix buffer-buffer credit extraction error
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix crash on session cleanup with unload
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    qla_dbg.c (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    qla_os.c (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    tcm_qla2xxx.c (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix I/O errors during LIP reset tests
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix I/O failures during remote port
    toggle testing (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix memory size truncation (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Fix MPI reset needed message (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Fix point-to-point (N2N) device discovery
    issue (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Fix reset of MPI firmware (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Honor status qualifier in FCP_RSP per
    spec (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Make tgt_port_database available in
    initiator mode (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Performance tweak (bsc#1171688
    bsc#1174003).

  - scsi: qla2xxx: Reduce duplicate code in reporting speed
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Remove unneeded variable 'rval'
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Setup debugfs entries for remote ports
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Update version to 10.02.00.102-k
    (bsc#1171688 bsc#1174003).

  - scsi: qla2xxx: Update version to 10.02.00.103-k
    (bsc#1171688 bsc#1174003).

  - sctp: not disable bh in the whole sctp_get_port_local()
    (networking-stable-20_09_11).

  - selftests/timers: Turn off timeout setting (git-fixes).

  - serial: 8250: 8250_omap: Terminate DMA before pushing
    data on RX timeout (git-fixes).

  - serial: 8250_mtk: Fix uart_get_baud_rate warning
    (git-fixes).

  - serial: 8250_omap: Fix sleeping function called from
    invalid context during probe (git-fixes).

  - serial: 8250_port: Do not service RX FIFO if throttled
    (git-fixes).

  - serial: txx9: add missing platform_driver_unregister()
    on error in serial_txx9_init (git-fixes).

  - serial: uartps: Wait for tx_empty in console setup
    (git-fixes).

  - slimbus: core: check get_addr before removing laddr ida
    (git-fixes).

  - slimbus: core: do not enter to clock pause mode in core
    (git-fixes).

  - slimbus: qcom-ngd-ctrl: disable ngd in qmi server down
    callback (git-fixes).

  - soc: fsl: qbman: Fix return value on success
    (git-fixes).

  - spi: dw-pci: free previously allocated IRQs if
    desc->setup() fails (git-fixes).

  - spi: fsl-espi: Only process interrupts for expected
    events (git-fixes).

  - spi: omap2-mcspi: Improve performance waiting for CHSTAT
    (git-fixes).

  - spi: spi-s3c64xx: Check return values (git-fixes).

  - spi: spi-s3c64xx: swap s3c64xx_spi_set_cs() and
    s3c64xx_enable_datapath() (git-fixes).

  - spi: sprd: Release DMA channel also on probe deferral
    (git-fixes).

  - spi: stm32: Rate-limit the 'Communication suspended'
    message (git-fixes).

  - staging: comedi: cb_pcidas: Allow 2-channel commands for
    AO subdevice (git-fixes).

  - staging: comedi: check validity of wMaxPacketSize of usb
    endpoints found (git-fixes).

  - staging: octeon: Drop on uncorrectable alignment or FCS
    error (git-fixes).

  - staging: octeon: repair 'fixed-link' support
    (git-fixes).

  - staging:r8188eu: avoid skb_clone for amsdu to msdu
    conversion (git-fixes).

  - staging: rtl8192u: Do not use GFP_KERNEL in atomic
    context (git-fixes).

  - SUNRPC: Revert 241b1f419f0e ('SUNRPC: Remove
    xdr_buf_trim()') (git-fixes).

  - svcrdma: Fix page leak in svc_rdma_recv_read_chunk()
    (git-fixes).

  - taprio: Fix allowing too small intervals
    (networking-stable-20_09_24).

  -
    target-compare-and-write-backend-driver-sense-handli.pat
    ch: (bsc#1177719).

  -
    target-rbd-add-emulate_legacy_capacity-dev-attribute.pat
    ch: (bsc#1177109).

  - target-rbd-add-WRITE-SAME-support.patch: (bsc#1177090).

  -
    target-rbd-conditionally-fix-off-by-one-bug-in-get_b.pat
    ch: (bsc#1177109).

  -
    target-rbd-detect-stripe_unit-SCSI-block-size-misali.pat
    ch: (bsc#1177090).

  -
    target-rbd-fix-unmap-discard-block-size-conversion.patch
    : (bsc#1177271).

  -
    target-rbd-fix-unmap-handling-with-unmap_zeroes_data.pat
    ch: (bsc#1177271).

  - target-rbd-support-COMPARE_AND_WRITE.patch:
    (bsc#1177090).

  - thermal: rcar_thermal: Handle probe error gracefully
    (git-fixes).

  - time: Prevent undefined behaviour in timespec64_to_ns()
    (bsc#1164648).

  - tipc: fix memory leak caused by tipc_buf_append()
    (git-fixes).

  - tipc: Fix memory leak in tipc_group_create_member()
    (networking-stable-20_09_24).

  - tipc: fix shutdown() of connectionless socket
    (networking-stable-20_09_11).

  - tipc: fix shutdown() of connection oriented socket
    (networking-stable-20_09_24).

  - tipc: fix the skb_unshare() in tipc_buf_append()
    (git-fixes).

  - tipc: fix uninit skb->data in tipc_nl_compat_dumpit()
    (networking-stable-20_08_24).

  - tipc: use skb_unshare() instead in tipc_buf_append()
    (networking-stable-20_09_24).

  - tracing: Check return value of __create_val_fields()
    before using its result (git-fixes).

  - tracing: Save normal string variables (git-fixes).

  - tty: ipwireless: fix error handling (git-fixes).

  - tty: serial: fsl_lpuart: fix lpuart32_poll_get_char
    (git-fixes).

  - uio: free uio id after uio file node is freed
    (git-fixes).

  - Update config files. Enable ACPI_PCI_SLOT and
    HOTPLUG_PCI_ACPI (bsc#1177194).

  - Update patches.suse/target-add-rbd-backend.patch: ().
    (simplify block to byte calculations and use consistent
    error paths)

  - USB: adutux: fix debugging (git-fixes).

  - usb: cdc-acm: add quirk to blacklist ETAS ES58X devices
    (git-fixes).

  - usb: cdc-acm: fix cooldown mechanism (git-fixes).

  - USB: cdc-acm: handle broken union descriptors
    (git-fixes).

  - USB: cdc-wdm: Make wdm_flush() interruptible and add
    wdm_fsync() (git-fixes).

  - usb: core: Solve race condition in anchor cleanup
    functions (git-fixes).

  - usb: dwc2: Fix INTR OUT transfers in DDMA mode
    (git-fixes).

  - usb: dwc2: Fix parameter type in function pointer
    prototype (git-fixes).

  - usb: dwc3: core: add phy cleanup for probe error
    handling (git-fixes).

  - usb: dwc3: core: do not trigger runtime pm when remove
    driver (git-fixes).

  - usb: dwc3: ep0: Fix ZLP for OUT ep0 requests
    (git-fixes).

  - usb: dwc3: gadget: Resume pending requests after
    CLEAR_STALL (git-fixes).

  - usb: dwc3: Increase timeout for CmdAct cleared by device
    controller (git-fixes).

  - usb: dwc3: pci: Allow Elkhart Lake to utilize DSM method
    for PM functionality (git-fixes).

  - usb: dwc3: simple: add support for Hikey 970
    (git-fixes).

  - USB: EHCI: ehci-mv: fix error handling in
    mv_ehci_probe() (git-fixes).

  - USB: EHCI: ehci-mv: fix less than zero comparison of an
    unsigned int (git-fixes).

  - usb: gadget: f_ncm: allow using NCM in SuperSpeed Plus
    gadgets (git-fixes).

  - usb: gadget: f_ncm: fix ncm_bitrate for SuperSpeed and
    above (git-fixes).

  - USB: gadget: f_ncm: Fix NDP16 datagram validation
    (git-fixes).

  - usb: gadget: function: printer: fix use-after-free in
    __lock_acquire (git-fixes).

  - usb: gadget: u_ether: enable qmult on SuperSpeed Plus as
    well (git-fixes).

  - usblp: fix race between disconnect() and read()
    (git-fixes).

  - usb: mtu3: fix panic in mtu3_gadget_stop() (git-fixes).

  - usb: ohci: Default to per-port over-current protection
    (git-fixes).

  - USB: serial: cyberjack: fix write-URB completion race
    (git-fixes).

  - USB: serial: ftdi_sio: add support for FreeCalypso
    JTAG+UART adapters (git-fixes).

  - USB: serial: option: add Cellient MPL200 card
    (git-fixes).

  - USB: serial: option: Add Telit FT980-KS composition
    (git-fixes).

  - USB: serial: pl2303: add device-id for HP GC device
    (git-fixes).

  - USB: serial: qcserial: fix altsetting probing
    (git-fixes).

  - usb: typec: tcpm: During PR_SWAP, source caps should be
    sent only after tSwapSourceStart (git-fixes).

  - usb: xhci-mtk: Fix typo (git-fixes).

  - usb: xhci: omit duplicate actions when suspending a
    runtime suspended host (git-fixes).

  - vfio/pci: Decouple PCI_COMMAND_MEMORY bit checks from
    is_virtfn (bsc#1176979).

  - video: hyperv: hyperv_fb: Obtain screen resolution from
    Hyper-V host (bsc#1175306).

  - video: hyperv: hyperv_fb: Support deferred IO for
    Hyper-V frame buffer driver (bsc#1175306).

  - video: hyperv: hyperv_fb: Use physical memory for fb on
    HyperV Gen 1 VMs (bsc#1175306).

  - virtio-net: do not disable guest csum when disable LRO
    (git-fixes).

  - VMCI: check return value of get_user_pages_fast() for
    errors (git-fixes).

  - vmxnet3: fix cksum offload issues for non-udp tunnels
    (git-fixes).

  - w1: mxc_w1: Fix timeout resolution problem leading to
    bus error (git-fixes).

  - watchdog: Fix memleak in watchdog_cdev_register
    (git-fixes).

  - watchdog: sp5100: Fix definition of EFCH_PM_DECODEEN3
    (git-fixes).

  - watchdog: Use put_device on error (git-fixes).

  - wcn36xx: Fix reported 802.11n rx_highest rate
    wcn3660/wcn3680 (git-fixes).

  - wlcore: fix runtime pm imbalance in wl1271_tx_work
    (git-fixes).

  - wlcore: fix runtime pm imbalance in
    wlcore_regdomain_config (git-fixes).

  - writeback: Avoid skipping inode writeback (bsc#1177755).

  - writeback: Fix sync livelock due to b_dirty_time
    processing (bsc#1177755).

  - writeback: Protect inode->i_io_list with inode->i_lock
    (bsc#1177755).

  - X.509: Add CodeSigning extended key usage parsing
    (bsc#1177353).

  - x86/alternative: Do not call text_poke() in lazy TLB
    mode (bsc#1175749).

  - x86/fpu: Allow multiple bits in clearcpuid= parameter
    (bsc#1152489).

  - x86/ioapic: Unbreak check_timer() (bsc#1152489).

  - x86/kexec: Use up-to-dated screen_info copy to fill boot
    params (bsc#1175306).

  - x86/(mce,mm): Unmap the entire page if the whole page is
    affected and poisoned (bsc#1177765).

  - x86/mm: unencrypted non-blocking DMA allocations use
    coherent pools (bsc#1175898, ECO-2743).

  - x86/unwind/orc: Fix inactive tasks with stack pointer in
    %sp on GCC 10 compiled kernels (bsc#1176907).

  - x86/xen: disable Firmware First mode for correctable
    memory errors (bsc#1176713).

  - xen/blkback: use lateeoi irq binding (XSA-332
    bsc#1177411).

  - xen/events: add a new 'late EOI' evtchn framework
    (XSA-332 bsc#1177411).

  - xen/events: add a proper barrier to 2-level uevent
    unmasking (XSA-332 bsc#1177411).

  - xen/events: avoid removing an event channel while
    handling it (XSA-331 bsc#1177410).

  - xen/events: block rogue events for some time (XSA-332
    bsc#1177411).

  - xen/events: defer eoi in case of excessive number of
    events (XSA-332 bsc#1177411).

  - xen/events: do not use chip_data for legacy IRQs
    (bsc#1065600).

  - xen/events: fix race in evtchn_fifo_unmask() (XSA-332
    bsc#1177411).

  - xen/events: switch user event channels to lateeoi model
    (XSA-332 bsc#1177411).

  - xen/events: use a common cpu hotplug hook for event
    channels (XSA-332 bsc#1177411).

  - xen/gntdev.c: Mark pages as dirty (bsc#1065600).

  - xen/netback: use lateeoi irq binding (XSA-332
    bsc#1177411).

  - xen/pciback: use lateeoi irq binding (XSA-332
    bsc#1177411).

  - xen/pvcallsback: use lateeoi irq binding (XSA-332
    bsc#1177411).

  - xen/scsiback: use lateeoi irq binding (XSA-332
    bsc#1177411).

  - xfs: complain if anyone tries to create a too-large
    buffer log item (bsc#1166146).

  - xfs: do not update mtime on COW faults (bsc#1167030).

  - xfs: fix high key handling in the rt allocator's
    query_range function (git-fixes).

  - xfs: fix scrub flagging rtinherit even if there is no rt
    device (git-fixes).

  - xfs: fix xfs_bmap_validate_extent_raw when checking attr
    fork of rt files (git-fixes).

  - xfs: flush new eof page on truncate to avoid post-eof
    corruption (git-fixes).

  - xfs: force the log after remapping a synchronous-writes
    file (git-fixes).

  - xfs: introduce XFS_MAX_FILEOFF (bsc#1166166).

  - xfs: limit entries returned when counting fsmap records
    (git-fixes).

  - xfs: remove unused variable 'done' (bsc#1166166).

  - xfs: set xefi_discard when creating a deferred agfl free
    log intent item (git-fixes).

  - xfs: truncate should remove all blocks, not just to the
    end of the page cache (bsc#1166166).

  - xhci: do not create endpoint debugfs entry before ring
    buffer is set (git-fixes).

  - xprtrdma: fix incorrect header size calculations
    (git-fixes).

  - yam: fix possible memory leak in yam_init_driver
    (git-fixes).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=802154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954532");
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.50.1.lp152.8.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.50.1.lp152.8.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-default-base / kernel-default-base-rebuild");
}
