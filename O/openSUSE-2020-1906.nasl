#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1906.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(142945);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-14351",
    "CVE-2020-16120",
    "CVE-2020-25285",
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25704",
    "CVE-2020-25705",
    "CVE-2020-8694"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1906)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

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

  - ACPI: Always build evged in (git-fixes).

  - ACPI: button: fix handling lid state changes when input
    device closed (git-fixes).

  - ACPI: configfs: Add missing config_item_put() to fix
    refcount leak (git-fixes).

  - acpi-cpufreq: Honor _PSD table setting on new AMD CPUs
    (git-fixes).

  - ACPI: debug: do not allow debugging when ACPI is
    disabled (git-fixes).

  - ACPI / extlog: Check for RDMSR failure (git-fixes).

  - ACPI: video: use ACPI backlight for HP 635 Notebook
    (git-fixes).

  - act_ife: load meta modules before tcf_idr_check_alloc()
    (networking-stable-20_09_24).

  - Add CONFIG_CHECK_CODESIGN_EKU

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

  - ASoC: codecs: wcd9335: Set digital gain range correctly
    (git-fixes).

  - ASoC: cs42l51: manage mclk shutdown delay (git-fixes).

  - ASoC: fsl: imx-es8328: add missing put_device() call in
    imx_es8328_probe() (git-fixes).

  - ASoC: fsl_sai: Instantiate snd_soc_dai_driver
    (git-fixes).

  - ASoC: Intel: kbl_rt5663_max98927: Fix kabylake_ssp_fixup
    function (git-fixes).

  - ASoC: qcom: lpass-cpu: fix concurrency issue
    (git-fixes).

  - ASoC: qcom: lpass-platform: fix memory leak (git-fixes).

  - ASoC: qcom: sdm845: set driver name correctly
    (git-fixes).

  - ASoC: sun50i-codec-analog: Fix duplicate use of ADC
    enable bits (git-fixes).

  - ASoC: tlv320aic32x4: Fix bdiv clock rate derivation
    (git-fixes).

  - ata: sata_rcar: Fix DMA boundary mask (git-fixes).

  - ath10k: check idx validity in
    __ath10k_htt_rx_ring_fill_n() (git-fixes).

  - ath10k: Fix the size used in a 'dma_free_coherent()'
    call in an error handling path (git-fixes).

  - ath10k: fix VHT NSS calculation when STBC is enabled
    (git-fixes).

  - ath10k: provide survey info as accumulated data
    (git-fixes).

  - ath10k: start recovery process when payload length
    exceeds max htc length for sdio (git-fixes).

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

  - Bluetooth: hci_uart: Cancel init work before
    unregistering (git-fixes).

  - Bluetooth: MGMT: Fix not checking if BT_HS is enabled
    (git-fixes).

  - Bluetooth: Only mark socket zapped after unlocking
    (git-fixes).

  - bnxt_en: Protect bnxt_set_eee() and
    bnxt_set_pauseparam() with mutex (git-fixes).

  - bonding: show saner speed for broadcast mode
    (networking-stable-20_08_24).

  - brcm80211: fix possible memleak in
    brcmf_proto_msgbuf_attach (git-fixes).

  - brcmfmac: check ndev pointer (git-fixes).

  - brcmsmac: fix memory leak in wlc_phy_attach_lcnphy
    (git-fixes).

  - btrfs: Account for merged patches upstream Move below
    patches to sorted section.

  - btrfs: add owner and fs_info to alloc_state io_tree
    (bsc#1177854).

  - btrfs: allocate scrub workqueues outside of locks
    (bsc#1178183).

  - btrfs: cleanup cow block on error (bsc#1178584).

  - btrfs: do not force read-only after error in drop
    snapshot (bsc#1176354).

  - btrfs: drop path before adding new uuid tree entry
    (bsc#1178176).

  - btrfs: fix filesystem corruption after a device replace
    (bsc#1178395).

  - btrfs: fix NULL pointer dereference after failure to
    create snapshot (bsc#1178190).

  - btrfs: fix overflow when copying corrupt csums for a
    message (bsc#1178191).

  - btrfs: fix space cache memory leak after transaction
    abort (bsc#1178173).

  - btrfs: move btrfs_rm_dev_replace_free_srcdev outside of
    all locks (bsc#1178395).

  - btrfs: move btrfs_scratch_superblocks into
    btrfs_dev_replace_finishing (bsc#1178395).

  - btrfs: qgroup: fix qgroup meta rsv leak for subvolume
    operations (bsc#1177856).

  - btrfs: qgroup: fix wrong qgroup metadata reserve for
    delayed inode (bsc#1177855).

  - btrfs: reschedule if necessary when logging directory
    items (bsc#1178585).

  - btrfs: send, orphanize first all conflicting inodes when
    processing references (bsc#1178579).

  - btrfs: send, recompute reference path after
    orphanization of a directory (bsc#1178581).

  - btrfs: set the correct lockdep class for new nodes
    (bsc#1178184).

  - btrfs: set the lockdep class for log tree extent buffers
    (bsc#1178186).

  - btrfs: tree-checker: fix false alert caused by legacy
    btrfs root item (bsc#1177861).

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

  - crypto: ccp - fix error handling (git-fixes).

  - cxgb4: fix memory leak during module unload
    (networking-stable-20_09_24).

  - cxgb4: Fix offset when clearing filter byte counters
    (networking-stable-20_09_24).

  - cxl: Rework error message for incompatible slots
    (bsc#1055014 git-fixes).

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

  - drivers: watchdog: rdc321x_wdt: Fix race condition bugs
    (git-fixes).

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

  - futex: Adjust absolute futex timeouts with per time
    namespace offset (bsc#1164648).

  - futex: Consistently use fshared as boolean
    (bsc#1149032).

  - futex: Fix incorrect should_fail_futex() handling
    (bsc#1149032).

  - futex: Remove put_futex_key() (bsc#1149032).

  - futex: Remove unused or redundant includes
    (bsc#1149032).

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

  - hyperv_fb: Update screen_info after removing old
    framebuffer (bsc#1175306).

  - i2c: core: Restore acpi_walk_dep_device_list() getting
    called after registering the ACPI i2c devs (git-fixes).

  - i2c: imx: Fix external abort on interrupt in exit paths
    (git-fixes).

  - i2c: rcar: Auto select RESET_CONTROLLER (git-fixes).

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

  - iio:accel:bma180: Fix use of true when should be
    iio_shared_by enum (git-fixes).

  - iio: adc: gyroadc: fix leak of device node iterator
    (git-fixes).

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

  - ima: Remove semicolon at the end of
    ima_get_binary_runtime_size() (git-fixes).

  - Input: ati_remote2 - add missing newlines when printing
    module parameters (git-fixes).

  - Input: ep93xx_keypad - fix handling of
    platform_get_irq() error (git-fixes).

  - Input: imx6ul_tsc - clean up some errors in
    imx6ul_tsc_resume() (git-fixes).

  - Input: omap4-keypad - fix handling of platform_get_irq()
    error (git-fixes).

  - Input: stmfts - fix a & vs && typo (git-fixes).

  - Input: sun4i-ps2 - fix handling of platform_get_irq()
    error (git-fixes).

  - Input: twl4030_keypad - fix handling of
    platform_get_irq() error (git-fixes).

  - iomap: Make sure iomap_end is called after iomap_begin
    (bsc#1177754).

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

  - kABI: Fix kABI after add CodeSigning extended key usage
    (bsc#1177353).

  - kallsyms: Refactor kallsyms_show_value() to take cred
    (git-fixes).

  - kbuild: enforce -Werror=return-type (bsc#1177281).

  - KVM: x86/mmu: Commit zap of remaining invalid pages when
    recovering lpages (git-fixes).

  - leds: bcm6328, bcm6358: use devres LED registering
    function (git-fixes).

  - leds: mt6323: move period calculation (git-fixes).

  - libceph: clear con->out_msg on Policy::stateful_server
    faults (bsc#1178177).

  - lib/crc32.c: fix trivial typo in preprocessor condition
    (git-fixes).

  - mac80211: handle lack of sband->bitrates in rates
    (git-fixes).

  - mailbox: avoid timer start from callback (git-fixes).

  - media: ati_remote: sanity check for both endpoints
    (git-fixes).

  - media: bdisp: Fix runtime PM imbalance on error
    (git-fixes).

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

  - media: media/pci: prevent memory leak in bttv_probe
    (git-fixes).

  - media: platform: Improve queue set up flow for bug
    fixing (git-fixes).

  - media: platform: s3c-camif: Fix runtime PM imbalance on
    error (git-fixes).

  - media: platform: sti: hva: Fix runtime PM imbalance on
    error (git-fixes).

  - media: rcar_drif: Allocate v4l2_async_subdev dynamically
    (git-fixes).

  - media: rcar_drif: Fix fwnode reference leak when parsing
    DT (git-fixes).

  - media: saa7134: avoid a shift overflow (git-fixes).

  - media: st-delta: Fix reference count leak in
    delta_run_work (git-fixes).

  - media: sti: Fix reference count leaks (git-fixes).

  - media: tw5864: check status of tw5864_frameinterval_get
    (git-fixes).

  - media: uvcvideo: Ensure all probed info is returned to
    v4l2 (git-fixes).

  - media: uvcvideo: Fix dereference of out-of-bound list
    iterator (git-fixes).

  - media: uvcvideo: Fix uvc_ctrl_fixup_xu_info() not having
    any effect (git-fixes).

  - media: venus: core: Fix runtime PM imbalance in
    venus_probe (git-fixes).

  - media: vsp1: Fix runtime PM imbalance on error
    (git-fixes).

  - memory: fsl-corenet-cf: Fix handling of
    platform_get_irq() error (git-fixes).

  - memory: omap-gpmc: Fix a couple off by ones (git-fixes).

  - memory: omap-gpmc: Fix build error without CONFIG_OF
    (git-fixes).

  - mfd: sm501: Fix leaks in probe() (git-fixes).

  - mic: vop: copy data to kernel space then write to io
    memory (git-fixes).

  - misc: mic: scif: Fix error handling path (git-fixes).

  - misc: rtsx: Fix memory leak in rtsx_pci_probe
    (git-fixes).

  - misc: vop: add round_up(x,4) for vring_size to avoid
    kernel panic (git-fixes).

  - mmc: sdio: Check for CISTPL_VERS_1 buffer size
    (git-fixes).

  - mm: do not panic when links can't be created in sysfs
    (bsc#1178002).

  - mm: do not rely on system state to detect hot-plug
    operations (bsc#1178002).

  - mm: fix a race during THP splitting (bsc#1178255).

  - mm/huge_memory.c: use head to check huge zero page
    (git-fixes (mm/thp)).

  - mm: madvise: fix vma user-after-free (git-fixes).

  - mm/mempolicy.c: fix out of bounds write in
    mpol_parse_str() (git-fixes (mm/mempolicy)).

  - mm/page-writeback.c: avoid potential division by zero in
    wb_min_max_ratio() (git-fixes (mm/writeback)).

  - mm/page-writeback.c: improve arithmetic divisions
    (git-fixes (mm/writeback)).

  - mm: replace memmap_context by meminit_context
    (bsc#1178002).

  - mm/rmap: fixup copying of soft dirty and uffd ptes
    (git-fixes (mm/rmap)).

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

  - mtd: lpddr: Fix bad logic in print_drs_error
    (git-fixes).

  - mtd: lpddr: fix excessive stack usage with clang
    (git-fixes).

  - mtd: mtdoops: Do not write panic data twice (git-fixes).

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

  - nl80211: fix non-split wiphy information (git-fixes).

  - NTB: hw: amd: fix an issue about leak system resources
    (git-fixes).

  - ntb: intel: Fix memleak in intel_ntb_pci_probe
    (git-fixes).

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

  - percpu: fix first chunk size calculation for populated
    bitmap (git-fixes (mm/percpu)).

  - perf/x86/amd: Fix sampling Large Increment per Cycle
    events (bsc#1152489).

  - perf/x86: Fix n_pair for cancelled txn (bsc#1152489).

  - pinctrl: mcp23s08: Fix mcp23x17 precious range
    (git-fixes).

  - pinctrl: mcp23s08: Fix mcp23x17_regmap initialiser
    (git-fixes).

  - PKCS#7: Check codeSigning EKU for kernel module and
    kexec pe verification.

  - PKCS#7: Check codeSigning EKU for kernel module and
    kexec pe verification (bsc#1177353).

  - platform/x86: mlx-platform: Remove PSU EEPROM
    configuration (git-fixes).

  - PM: hibernate: Batch hibernate and resume IO requests
    (bsc#1178079).

  - PM: hibernate: remove the bogus call to get_gendisk() in
    software_resume() (git-fixes).

  - PM: runtime: Drop runtime PM references to supplier on
    link removal (git-fixes).

  - powerpc/book3s64/radix: Make radix_mem_block_size 64bit
    (bsc#1055186 ltc#153436 git-fixes).

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

  - power: supply: test_power: add missing newlines when
    printing parameters by sysfs (git-fixes).

  - pwm: img: Fix NULL pointer access in probe (git-fixes).

  - pwm: lpss: Add range limit check for the base_unit
    register value (git-fixes).

  - pwm: lpss: Fix off by one error in base_unit math in
    pwm_lpss_prepare() (git-fixes).

  - qtnfmac: fix resource leaks on unsupported iftype error
    return path (git-fixes).

  - r8169: fix issue with forced threading in combination
    with shared interrupts (git-fixes).

  - r8169: fix operation under forced interrupt threading
    (git-fixes).

  - rapidio: fix the missed put_device() for
    rio_mport_add_riodev (git-fixes).

  - regulator: defer probe when trying to get voltage from
    unresolved supply (git-fixes).

  - reset: sti: reset-syscfg: fix struct description
    warnings (git-fixes).

  - ring-buffer: Return 0 on success from
    ring_buffer_resize() (git-fixes).

  - rpm/kernel-module-subpackage: make Group tag optional
    (bsc#1163592)

  - rtc: rx8010: do not modify the global rtc ops
    (git-fixes).

  - rtl8xxxu: prevent potential memory leak (git-fixes).

  - rtw88: increse the size of rx buffer size (git-fixes).

  - s390/cio: add cond_resched() in the slow_eval_known_fn()
    loop (bsc#1177799 LTC#188733).

  - s390/dasd: Fix zero write for FBA devices (bsc#1177801
    LTC#188735).

  - scsi: ibmvfc: Fix error return in ibmvfc_probe()
    (bsc#1065729).

  - scsi: ibmvscsi: Fix potential race after loss of
    transport (bsc#1178166 ltc#188226).

  - scsi: mptfusion: Do not use GFP_ATOMIC for larger DMA
    allocations (bsc#1175898, ECO-2743).

  - sctp: not disable bh in the whole sctp_get_port_local()
    (networking-stable-20_09_11).

  - selftests/timers: Turn off timeout setting (git-fixes).

  - serial: 8250_mtk: Fix uart_get_baud_rate warning
    (git-fixes).

  - serial: txx9: add missing platform_driver_unregister()
    on error in serial_txx9_init (git-fixes).

  - slimbus: core: check get_addr before removing laddr ida
    (git-fixes).

  - slimbus: core: do not enter to clock pause mode in core
    (git-fixes).

  - slimbus: qcom-ngd-ctrl: disable ngd in qmi server down
    callback (git-fixes).

  - soc: fsl: qbman: Fix return value on success
    (git-fixes).

  - spi: spi-s3c64xx: Check return values (git-fixes).

  - spi: spi-s3c64xx: swap s3c64xx_spi_set_cs() and
    s3c64xx_enable_datapath() (git-fixes).

  - staging: comedi: cb_pcidas: Allow 2-channel commands for
    AO subdevice (git-fixes).

  - staging: comedi: check validity of wMaxPacketSize of usb
    endpoints found (git-fixes).

  - staging: octeon: Drop on uncorrectable alignment or FCS
    error (git-fixes).

  - staging: octeon: repair 'fixed-link' support
    (git-fixes).

  - staging: rtl8192u: Do not use GFP_KERNEL in atomic
    context (git-fixes).

  - taprio: Fix allowing too small intervals
    (networking-stable-20_09_24).

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

  - usb: dwc3: pci: Allow Elkhart Lake to utilize DSM method
    for PM functionality (git-fixes).

  - usb: dwc3: simple: add support for Hikey 970
    (git-fixes).

  - usb: gadget: f_ncm: allow using NCM in SuperSpeed Plus
    gadgets (git-fixes).

  - usb: gadget: f_ncm: fix ncm_bitrate for SuperSpeed and
    above (git-fixes).

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

  - video: hyperv: hyperv_fb: Obtain screen resolution from
    Hyper-V host (bsc#1175306).

  - video: hyperv: hyperv_fb: Support deferred IO for
    Hyper-V frame buffer driver (bsc#1175306).

  - video: hyperv: hyperv_fb: Use physical memory for fb on
    HyperV Gen 1 VMs (bsc#1175306).

  - VMCI: check return value of get_user_pages_fast() for
    errors (git-fixes).

  - w1: mxc_w1: Fix timeout resolution problem leading to
    bus error (git-fixes).

  - watchdog: Fix memleak in watchdog_cdev_register
    (git-fixes).

  - watchdog: sp5100: Fix definition of EFCH_PM_DECODEEN3
    (git-fixes).

  - watchdog: Use put_device on error (git-fixes).

  - wcn36xx: Fix reported 802.11n rx_highest rate
    wcn3660/wcn3680 (git-fixes).

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
    buffer is set (git-fixes).");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177470");
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
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
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

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.50.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.50.1") ) flag++;

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
