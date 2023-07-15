#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1901.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142921);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-0430", "CVE-2020-14351", "CVE-2020-16120", "CVE-2020-25285", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-8694");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1901)");
  script_summary(english:"Check for the openSUSE-2020-1901 patch");

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

  - CVE-2020-25668: Fixed concurrency use-after-free in
    con_font_op (bnc#1178123).

  - CVE-2020-25656: Fixed race condition in kbd code
    (bnc#1177766).

  - CVE-2020-25285: A race condition between hugetlb sysctl
    handlers in mm/hugetlb.c kernel could be used by local
    attackers to corrupt memory, cause a NULL pointer
    dereference, or possibly have unspecified other impact,
    aka CID-17743798d812 (bnc#1176485).

  - CVE-2020-0430: In skb_headlen of
    /include/linux/skbuff.h, there is a possible out of
    bounds read due to memory corruption. This could lead to
    local escalation of privilege with no additional
    execution privileges needed. User interaction is not
    needed for exploitation (bnc#1176723).

  - CVE-2020-14351: Fixed race in the perf_mmap_close()
    function (bsc#1177086).

  - CVE-2020-16120: Fixed verify permissions in
    ovl_path_open() (bsc#1177470).

  - CVE-2020-8694: Restrict energy meter to root access to
    avoid side channel attack (bsc#1170415).

The following non-security bugs were fixed :

  - 9P: Cast to loff_t before multiplying (git-fixes).

  - ACPI / extlog: Check for RDMSR failure (git-fixes).

  - ACPI: debug: do not allow debugging when ACPI is
    disabled (git-fixes).

  - ACPI: dock: fix enum-conversion warning (git-fixes).

  - ACPI: video: use ACPI backlight for HP 635 Notebook
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

  - ALSA: hda - Do not register a cb func if it is
    registered already (git-fixes).

  - ALSA: hda - Fix the return value if cb func is already
    registered (git-fixes).

  - ALSA: hda/realtek - Add mute Led support for HP
    Elitebook 845 G7 (git-fixes).

  - ALSA: hda/realtek - The front Mic on a HP machine does
    not work (git-fixes).

  - ALSA: hda/realtek: Enable audio jacks of ASUS D700SA
    with ALC887 (git-fixes).

  - ALSA: hda: auto_parser: remove shadowed variable
    declaration (git-fixes).

  - ALSA: hda: prevent undefined shift in
    snd_hdac_ext_bus_get_link() (git-fixes).

  - ALSA: hda: use semicolons rather than commas to separate
    statements (git-fixes).

  - ALSA: mixart: Correct comment wrt obsoleted tasklet
    usage (git-fixes).

  - ALSA: rawmidi: (cosmetic) align function parameters
    (git-fixes).

  - ALSA: seq: oss: Avoid mutex lock for a long-time ioctl
    (git-fixes).

  - ALSA: usb-audio: Add mixer support for Pioneer DJ
    DJM-250MK2 (git-fixes).

  - ALSA: usb-audio: endpoint.c: fix repeated word 'there'
    (git-fixes).

  - ALSA: usb-audio: fix spelling mistake 'Frequence' ->
    'Frequency' (git-fixes).

  - ASoC: qcom: lpass-cpu: fix concurrency issue
    (git-fixes).

  - ASoC: qcom: lpass-platform: fix memory leak (git-fixes).

  - Add cherry-picked ids for already backported DRM radeon
    patches

  - Bluetooth: MGMT: Fix not checking if BT_HS is enabled
    (git-fixes).

  - Bluetooth: Only mark socket zapped after unlocking
    (git-fixes).

  - EDAC/i5100: Fix error handling order in i5100_init_one()
    (bsc#1112178).

  - Fix use after free in get_capset_info callback
    (git-fixes).

  - HID: roccat: add bounds checking in
    kone_sysfs_write_settings() (git-fixes).

  - HID: wacom: Avoid entering wacom_wac_pen_report for pad
    / battery (git-fixes).

  - Input: ep93xx_keypad - fix handling of
    platform_get_irq() error (git-fixes).

  - Input: i8042 - add nopnp quirk for Acer Aspire 5 A515
    (git-fixes).

  - Input: imx6ul_tsc - clean up some errors in
    imx6ul_tsc_resume() (git-fixes).

  - Input: omap4-keypad - fix handling of platform_get_irq()
    error (git-fixes).

  - Input: sun4i-ps2 - fix handling of platform_get_irq()
    error (git-fixes).

  - Input: twl4030_keypad - fix handling of
    platform_get_irq() error (git-fixes).

  - NTB: hw: amd: fix an issue about leak system resources
    (git-fixes).

  - USB: adutux: fix debugging (git-fixes).

  - USB: cdc-acm: handle broken union descriptors
    (git-fixes).

  - USB: cdc-wdm: Make wdm_flush() interruptible and add
    wdm_fsync() (git-fixes).

  - USB: serial: qcserial: fix altsetting probing
    (git-fixes).

  - VMCI: check return value of get_user_pages_fast() for
    errors (git-fixes).

  - XEN uses irqdesc::irq_data_common::handler_data to store
    a per interrupt XEN data pointer which contains XEN
    specific information (XSA-332 bsc#1065600).

  - acpi-cpufreq: Honor _PSD table setting on new AMD CPUs
    (git-fixes).

  - ata: sata_rcar: Fix DMA boundary mask (git-fixes).

  - ath10k: Fix the size used in a 'dma_free_coherent()'
    call in an error handling path (git-fixes).

  - ath10k: check idx validity in
    __ath10k_htt_rx_ring_fill_n() (git-fixes).

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

  - backlight: sky81452-backlight: Fix refcount imbalance on
    error (git-fixes).

  - blk-mq: order adding requests to hctx->dispatch and
    checking SCHED_RESTART (bsc#1177750).

  - block: ensure bdi->io_pages is always initialized
    (bsc#1177749).

  - bnxt: do not enable NAPI until rings are ready
    (networking-stable-20_09_11).

  - bnxt_en: Check for zero dir entries in NVRAM
    (networking-stable-20_09_11).

  - brcm80211: fix possible memleak in
    brcmf_proto_msgbuf_attach (git-fixes).

  - brcmfmac: check ndev pointer (git-fixes).

  - brcmsmac: fix memory leak in wlc_phy_attach_lcnphy
    (git-fixes).

  - btrfs: check the right error variable in
    btrfs_del_dir_entries_in_log (bsc#1177687).

  - btrfs: do not force read-only after error in drop
    snapshot (bsc#1176354).

  - btrfs: do not set the full sync flag on the inode during
    page release (bsc#1177687).

  - btrfs: fix incorrect updating of log root tree
    (bsc#1177687).

  - btrfs: fix race between page release and a fast fsync
    (bsc#1177687).

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

  - btrfs: remove no longer needed use of log_writers for
    the log root tree (bsc#1177687).

  - btrfs: remove root usage from can_overcommit
    (bsc#1131277).

  - btrfs: stop incremening log_batch for the log root tree
    when syncing log (bsc#1177687).

  - btrfs: take overcommit into account in
    inc_block_group_ro (bsc#1176560).

  - btrfs: tree-checker: fix false alert caused by legacy
    btrfs root item (bsc#1177861).

  - bus/fsl_mc: Do not rely on caller to provide non NULL
    mc_io (git-fixes).

  - can: c_can: reg_map_(c,d)_can: mark as __maybe_unused
    (git-fixes).

  - can: can_create_echo_skb(): fix echo skb generation:
    always use skb_clone() (git-fixes).

  - can: dev: __can_get_echo_skb(): fix real payload length
    return value for RTR frames (git-fixes).

  - can: dev: can_get_echo_skb(): prevent call to
    kfree_skb() in hard IRQ context (git-fixes).

  - can: flexcan: flexcan_chip_stop(): add error handling
    and propagate error value (git-fixes).

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

  - ceph: fix memory leak in ceph_cleanup_snapid_map()
    (bsc#1178234).

  - ceph: map snapid to anonymous bdev ID (bsc#1178234).

  - ceph: promote to unsigned long long before shifting
    (bsc#1178187).

  - clk: at91: clk-main: update key before writing
    AT91_CKGR_MOR (git-fixes).

  - clk: at91: remove the checking of parent_name
    (git-fixes).

  - clk: bcm2835: add missing release if
    devm_clk_hw_register fails (git-fixes).

  - clk: imx8mq: Fix usdhc parents order (git-fixes).

  - clk: ti: clockdomain: fix static checker warning
    (git-fixes).

  - coredump: fix crash when umh is disabled (bsc#1177753).

  - crypto: algif_skcipher - EBUSY on aio should be an error
    (git-fixes).

  - crypto: bcm - Verify GCM/CCM key length in setkey
    (git-fixes).

  - crypto: ccp - fix error handling (git-fixes).

  - crypto: ixp4xx - Fix the size used in a
    'dma_free_coherent()' call (git-fixes).

  - crypto: mediatek - Fix wrong return value in
    mtk_desc_ring_alloc() (git-fixes).

  - crypto: omap-sham - fix digcnt register handling with
    export/import (git-fixes).

  - cxl: Rework error message for incompatible slots
    (bsc#1055014 git-fixes).

  - cypto: mediatek - fix leaks in mtk_desc_ring_alloc
    (git-fixes).

  - device property: Do not clear secondary pointer for
    shared primary firmware node (git-fixes).

  - device property: Keep secondary firmware node secondary
    by type (git-fixes).

  - dmaengine: dma-jz4780: Fix race in jz4780_dma_tx_status
    (git-fixes).

  - drm/amd/display: Do not invoke kgdb_breakpoint()
    unconditionally (git-fixes).

  - drm/amd/display: HDMI remote sink need mode validation
    for Linux (git-fixes).

  - drm/amdgpu: do not map BO in reserved region
    (git-fixes).

  - drm/amdgpu: prevent double kfree ttm->sg (git-fixes).

  - drm/bridge/synopsys: dsi: add support for non-continuous
    HS clock (git-fixes).

  - drm/brige/megachips: Add checking if
    ge_b850v3_lvds_init() is working correctly (git-fixes).

  - drm/gma500: fix error check (git-fixes).

  - drm/i915: Force VT'd workarounds when running as a guest
    OS (git-fixes).

  - drm/imx: tve remove extraneous type qualifier
    (git-fixes).

  - drm/msm: Drop debug print in _dpu_crtc_setup_lm_bounds()
    (git-fixes).

  - drm/nouveau/mem: guard against NULL pointer access in
    mem_del (git-fixes).

  - drm/ttm: fix eviction valuable range check (git-fixes).

  - eeprom: at25: set minimum read/write access stride to 1
    (git-fixes).

  - efivarfs: Replace invalid slashes with exclamation marks
    in dentries (git-fixes).

  - gre6: Fix reception with IP6_TNL_F_RCV_DSCP_COPY
    (networking-stable-20_08_24).

  - gtp: add GTPA_LINK info to msg sent to userspace
    (networking-stable-20_09_11).

  - i2c: imx: Fix external abort on interrupt in exit paths
    (git-fixes).

  - ibmveth: Identify ingress large send packets
    (bsc#1178185 ltc#188897).

  - ibmveth: Switch order of ibmveth_helper calls
    (bsc#1061843 git-fixes).

  - ibmvnic: fix ibmvnic_set_mac (bsc#1066382 ltc#160943
    git-fixes).

  - ibmvnic: save changed mac address to adapter->mac_addr
    (bsc#1134760 ltc#177449 git-fixes).

  - icmp: randomize the global rate limiter (git-fixes).

  - iio:accel:bma180: Fix use of true when should be
    iio_shared_by enum (git-fixes).

  - iio:adc:max1118 Fix alignment of timestamp and data leak
    issues (git-fixes).

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

  - ima: Remove semicolon at the end of
    ima_get_binary_runtime_size() (git-fixes).

  - include/linux/swapops.h: correct guards for
    non_swap_entry() (git-fixes (mm/swap)).

  - iomap: Make sure iomap_end is called after iomap_begin
    (bsc#1177754).

  - ip: fix tos reflection in ack and reset packets
    (networking-stable-20_09_24).

  - ipv4: Restore flowi4_oif update before call to
    xfrm_lookup_route (git-fixes).

  - ipv4: Update exception handling for multipath routes via
    same device (networking-stable-20_09_24).

  - iwlwifi: mvm: split a print to avoid a WARNING in ROC
    (git-fixes).

  - kbuild: enforce -Werror=return-type (bsc#1177281).

  - leds: bcm6328, bcm6358: use devres LED registering
    function (git-fixes).

  - leds: mt6323: move period calculation (git-fixes).

  - lib/crc32.c: fix trivial typo in preprocessor condition
    (git-fixes).

  - libceph: clear con->out_msg on Policy::stateful_server
    faults (bsc#1178188).

  - mac80211: handle lack of sband->bitrates in rates
    (git-fixes).

  - mailbox: avoid timer start from callback (git-fixes).

  - media: Revert 'media: exynos4-is: Add missed check for
    pinctrl_lookup_state()' (git-fixes).

  - media: ati_remote: sanity check for both endpoints
    (git-fixes).

  - media: bdisp: Fix runtime PM imbalance on error
    (git-fixes).

  - media: exynos4-is: Fix a reference count leak
    (git-fixes).

  - media: exynos4-is: Fix a reference count leak due to
    pm_runtime_get_sync (git-fixes).

  - media: exynos4-is: Fix several reference count leaks due
    to pm_runtime_get_sync (git-fixes).

  - media: firewire: fix memory leak (git-fixes).

  - media: m5mols: Check function pointer in
    m5mols_sensor_power (git-fixes).

  - media: media/pci: prevent memory leak in bttv_probe
    (git-fixes).

  - media: omap3isp: Fix memleak in isp_probe (git-fixes).

  - media: platform: Improve queue set up flow for bug
    fixing (git-fixes).

  - media: platform: fcp: Fix a reference count leak
    (git-fixes).

  - media: platform: s3c-camif: Fix runtime PM imbalance on
    error (git-fixes).

  - media: platform: sti: hva: Fix runtime PM imbalance on
    error (git-fixes).

  - media: s5p-mfc: Fix a reference count leak (git-fixes).

  - media: saa7134: avoid a shift overflow (git-fixes).

  - media: st-delta: Fix reference count leak in
    delta_run_work (git-fixes).

  - media: sti: Fix reference count leaks (git-fixes).

  - media: tc358743: initialize variable (git-fixes).

  - media: ti-vpe: Fix a missing check and reference count
    leak (git-fixes).

  - media: tuner-simple: fix regression in
    simple_set_radio_freq (git-fixes).

  - media: tw5864: check status of tw5864_frameinterval_get
    (git-fixes).

  - media: usbtv: Fix refcounting mixup (git-fixes).

  - media: uvcvideo: Ensure all probed info is returned to
    v4l2 (git-fixes).

  - media: vsp1: Fix runtime PM imbalance on error
    (git-fixes).

  - memory: fsl-corenet-cf: Fix handling of
    platform_get_irq() error (git-fixes).

  - memory: omap-gpmc: Fix a couple off by ones (git-fixes).

  - mfd: sm501: Fix leaks in probe() (git-fixes).

  - mic: vop: copy data to kernel space then write to io
    memory (git-fixes).

  - misc: mic: scif: Fix error handling path (git-fixes).

  - misc: rtsx: Fix memory leak in rtsx_pci_probe
    (git-fixes).

  - misc: vop: add round_up(x,4) for vring_size to avoid
    kernel panic (git-fixes).

  - mlx5 PPC ringsize workaround (bsc#1173432).

  - mlx5: remove support for ib_get_vector_affinity
    (bsc#1174748).

  - mm, numa: fix bad pmd by atomically check for
    pmd_trans_huge when marking page tables prot_numa
    (git-fixes (mm/numa)).

  - mm/huge_memory.c: use head to check huge zero page
    (git-fixes (mm/thp)).

  - mm/ksm.c: do not WARN if page is still mapped in
    remove_stable_node() (git-fixes (mm/hugetlb)).

  - mm/mempolicy.c: fix out of bounds write in
    mpol_parse_str() (git-fixes (mm/mempolicy)).

  - mm/mempolicy.c: use match_string() helper to simplify
    the code (git-fixes (mm/mempolicy)).

  - mm/page-writeback.c: avoid potential division by zero in
    wb_min_max_ratio() (git-fixes (mm/writeback)).

  - mm/page-writeback.c: improve arithmetic divisions
    (git-fixes (mm/writeback)).

  - mm/page-writeback.c: use div64_ul() for
    u64-by-unsigned-long divide (git-fixes (mm/writeback)).

  - mm/page_owner.c: remove drain_all_pages from
    init_early_allocated_pages (git-fixes (mm/debug)).

  - mm/rmap: fixup copying of soft dirty and uffd ptes
    (git-fixes (mm/rmap)).

  - mm/zsmalloc.c: fix build when CONFIG_COMPACTION=n
    (git-fixes (mm/zsmalloc)).

  - mm/zsmalloc.c: fix race condition in zs_destroy_pool
    (git-fixes (mm/zsmalloc)).

  - mm/zsmalloc.c: fix the migrated zspage statistics
    (git-fixes (mm/zsmalloc)).

  - mm/zsmalloc.c: migration can leave pages in ZS_EMPTY
    indefinitely (git-fixes (mm/zsmalloc)).

  - mm: hugetlb: switch to css_tryget() in
    hugetlb_cgroup_charge_cgroup() (git-fixes (mm/hugetlb)).

  - mmc: sdhci-of-esdhc: set timeout to max before tuning
    (git-fixes).

  - mmc: sdio: Check for CISTPL_VERS_1 buffer size
    (git-fixes).

  - mtd: lpddr: Fix bad logic in print_drs_error
    (git-fixes).

  - mtd: lpddr: fix excessive stack usage with clang
    (git-fixes).

  - mtd: mtdoops: Do not write panic data twice (git-fixes).

  - mwifiex: Do not use GFP_KERNEL in atomic context
    (git-fixes).

  - mwifiex: Remove unnecessary braces from
    HostCmd_SET_SEQ_NO_BSS_INFO (git-fixes).

  - mwifiex: do not call del_timer_sync() on uninitialized
    timer (git-fixes).

  - mwifiex: fix double free (git-fixes).

  - mwifiex: remove function pointer check (git-fixes).

  - net/mlx5e: Take common TIR context settings into a
    function (bsc#1177740).

  - net/mlx5e: Turn on HW tunnel offload in all TIRs
    (bsc#1177740).

  - net: Fix potential wrong skb->protocol in
    skb_vlan_untag() (networking-stable-20_08_24).

  - net: disable netpoll on fresh napis
    (networking-stable-20_09_11).

  - net: fec: Fix PHY init after
    phy_reset_after_clk_enable() (git-fixes).

  - net: fec: Fix phy_device lookup for
    phy_reset_after_clk_enable() (git-fixes).

  - net: hns: Fix memleak in hns_nic_dev_probe
    (networking-stable-20_09_11).

  - net: ipv6: fix kconfig dependency warning for
    IPV6_SEG6_HMAC (networking-stable-20_09_24).

  - net: phy: Avoid NPD upon phy_detach() when driver is
    unbound (networking-stable-20_09_24).

  - net: qrtr: fix usage of idr in port assignment to socket
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

  - netlabel: fix problems with mapping removal
    (networking-stable-20_09_11).

  - nfc: Ensure presence of NFC_ATTR_FIRMWARE_NAME attribute
    in nfc_genl_fw_download() (git-fixes).

  - nl80211: fix non-split wiphy information (git-fixes).

  - nvme-rdma: fix crash due to incorrect cqe (bsc#1174748).

  - nvme-rdma: fix crash when connect rejected
    (bsc#1174748).

  - nvme: do not update disk info for multipathed device
    (bsc#1171558).

  - p54: avoid accessing the data mapped to streaming DMA
    (git-fixes).

  - platform/x86: mlx-platform: Remove PSU EEPROM
    configuration (git-fixes).

  - power: supply: test_power: add missing newlines when
    printing parameters by sysfs (git-fixes).

  - powerpc/hwirq: Remove stale forward irq_chip declaration
    (bsc#1065729).

  - powerpc/icp-hv: Fix missing of_node_put() in success
    path (bsc#1065729).

  - powerpc/irq: Drop forward declaration of struct
    irqaction (bsc#1065729).

  - powerpc/perf/hv-gpci: Fix starting index value
    (bsc#1065729).

  - powerpc/powernv/dump: Fix race while processing OPAL
    dump (bsc#1065729).

  - powerpc/powernv/elog: Fix race while processing OPAL
    error log event (bsc#1065729).

  - powerpc/pseries: Fix missing of_node_put() in rng_init()
    (bsc#1065729).

  - powerpc/pseries: explicitly reschedule during drmem_lmb
    list traversal (bsc#1077428 ltc#163882 git-fixes).

  - powerpc: Fix undetected data corruption with P9N DD2.1
    VSX CI load emulation (bsc#1065729).

  - pty: do tty_flip_buffer_push without port->lock in
    pty_write (git-fixes).

  - pwm: lpss: Add range limit check for the base_unit
    register value (git-fixes).

  - pwm: lpss: Fix off by one error in base_unit math in
    pwm_lpss_prepare() (git-fixes).

  - regulator: defer probe when trying to get voltage from
    unresolved supply (git-fixes).

  - regulator: resolve supply after creating regulator
    (git-fixes).

  - ring-buffer: Return 0 on success from
    ring_buffer_resize() (git-fixes).

  - rpm/kernel-module-subpackage: make Group tag optional
    (bsc#1163592)

  - rtl8xxxu: prevent potential memory leak (git-fixes).

  - scsi: ibmvfc: Fix error return in ibmvfc_probe()
    (bsc#1065729).

  - scsi: ibmvscsi: Fix potential race after loss of
    transport (bsc#1178166 ltc#188226).

  - sctp: not disable bh in the whole sctp_get_port_local()
    (networking-stable-20_09_11).

  - spi: fsl-espi: Only process interrupts for expected
    events (git-fixes).

  - staging: comedi: cb_pcidas: Allow 2-channel commands for
    AO subdevice (git-fixes).

  - staging: octeon: Drop on uncorrectable alignment or FCS
    error (git-fixes).

  - staging: octeon: repair 'fixed-link' support
    (git-fixes).

  -
    target-rbd-fix-unmap-discard-block-size-conversion.patch
    : (bsc#1177271).

  -
    target-use-scsi_set_sense_information-helper-on-misc.pat
    ch: (bsc#1177719).

  - tg3: Fix soft lockup when tg3_reset_task() fails
    (networking-stable-20_09_11).

  - tipc: fix memory leak caused by tipc_buf_append()
    (git-fixes).

  - tipc: fix shutdown() of connection oriented socket
    (networking-stable-20_09_24).

  - tipc: fix shutdown() of connectionless socket
    (networking-stable-20_09_11).

  - tipc: fix the skb_unshare() in tipc_buf_append()
    (git-fixes).

  - tipc: fix uninit skb->data in tipc_nl_compat_dumpit()
    (networking-stable-20_08_24).

  - tipc: use skb_unshare() instead in tipc_buf_append()
    (networking-stable-20_09_24).

  - tty: ipwireless: fix error handling (git-fixes).

  - tty: serial: earlycon dependency (git-fixes).

  - tty: serial: fsl_lpuart: fix lpuart32_poll_get_char
    (git-fixes).

  - usb: cdc-acm: add quirk to blacklist ETAS ES58X devices
    (git-fixes).

  - usb: cdc-acm: fix cooldown mechanism (git-fixes).

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

  - usb: gadget: f_ncm: allow using NCM in SuperSpeed Plus
    gadgets (git-fixes).

  - usb: gadget: f_ncm: fix ncm_bitrate for SuperSpeed and
    above (git-fixes).

  - usb: gadget: function: printer: fix use-after-free in
    __lock_acquire (git-fixes).

  - usb: gadget: u_ether: enable qmult on SuperSpeed Plus as
    well (git-fixes).

  - usb: host: fsl-mph-dr-of: check return of dma_set_mask()
    (git-fixes).

  - usb: mtu3: fix panic in mtu3_gadget_stop() (git-fixes).

  - usb: ohci: Default to per-port over-current protection
    (git-fixes).

  - usb: typec: tcpm: During PR_SWAP, source caps should be
    sent only after tSwapSourceStart (git-fixes).

  - usb: typec: tcpm: reset hard_reset_count for any
    disconnect (git-fixes).

  - vfs: fix FIGETBSZ ioctl on an overlayfs file
    (bsc#1178202).

  - video: fbdev: pvr2fb: initialize variables (git-fixes).

  - video: fbdev: sis: fix null ptr dereference (git-fixes).

  - video: fbdev: vga16fb: fix setting of pixclock because a
    pass-by-value error (git-fixes).

  - w1: mxc_w1: Fix timeout resolution problem leading to
    bus error (git-fixes).

  - watchdog: iTCO_wdt: Export vendorsupport (bsc#1177101).

  - watchdog: iTCO_wdt: Make ICH_RES_IO_SMI optional
    (bsc#1177101).

  - wcn36xx: Fix reported 802.11n rx_highest rate
    wcn3660/wcn3680 (git-fixes).

  - writeback: Avoid skipping inode writeback (bsc#1177755).

  - writeback: Fix sync livelock due to b_dirty_time
    processing (bsc#1177755).

  - writeback: Protect inode->i_io_list with inode->i_lock
    (bsc#1177755).

  - x86, fakenuma: Fix invalid starting node ID (git-fixes
    (mm/x86/fakenuma)).

  - x86/apic: Unify duplicated local apic timer clockevent
    initialization (bsc#1112178).

  - x86/fpu: Allow multiple bits in clearcpuid= parameter
    (bsc#1112178).

  - x86/unwind/orc: Fix inactive tasks with stack pointer in
    %sp on GCC 10 compiled kernels (bsc#1058115
    bsc#1176907).

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
    (XSA-332 bsc#1065600).

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

  - xen/scsiback: use lateeoi irq binding (XSA-332
    bsc#1177411).

  - xfs: avoid infinite loop when cancelling CoW blocks
    after writeback failure (bsc#1178027).

  - xfs: do not update mtime on COW faults (bsc#1167030).

  - xfs: flush new eof page on truncate to avoid post-eof
    corruption (git-fixes).

  - xfs: limit entries returned when counting fsmap records
    (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061843"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936888"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25668");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.79.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.79.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.79.1") ) flag++;

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
