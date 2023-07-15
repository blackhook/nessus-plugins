#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-935.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138727);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2019-19462", "CVE-2019-20810", "CVE-2019-20812", "CVE-2020-10711", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10773", "CVE-2020-12656", "CVE-2020-12769", "CVE-2020-12888", "CVE-2020-13143", "CVE-2020-13974", "CVE-2020-14416");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-935)");
  script_summary(english:"Check for the openSUSE-2020-935 patch");

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

  - CVE-2019-19462: relay_open in kernel/relay.c allowed
    local users to cause a denial of service (such as relay
    blockage) by triggering a NULL alloc_percpu result
    (bnc#1158265).

  - CVE-2019-20810: go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c did not call
    snd_card_free for a failure path, which causes a memory
    leak, aka CID-9453264ef586 (bnc#1172458).

  - CVE-2019-20812: The prb_calc_retire_blk_tmo() function
    in net/packet/af_packet.c can result in a denial of
    service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka CID-b43d1f9f7067
    (bnc#1172453).

  - CVE-2020-10711: A NULL pointer dereference flaw was
    found in the Linux kernel's SELinux subsystem. This flaw
    occurs while importing the Commercial IP Security Option
    (CIPSO) protocol's category bitmap into the SELinux
    extensible bitmap via the' ebitmap_netlbl_import'
    routine. While processing the CIPSO restricted bitmap
    tag in the 'cipso_v4_parsetag_rbm' routine, it sets the
    security attribute to indicate that the category bitmap
    is present, even if it has not been allocated. This
    issue leads to a NULL pointer dereference issue while
    importing the same category bitmap into SELinux. This
    flaw allowed a remote network user to crash the system
    kernel, resulting in a denial of service (bnc#1171191).

  - CVE-2020-10732: A flaw was found in the implementation
    of Userspace core dumps. This flaw allowed an attacker
    with a local account to crash a trivial program and
    exfiltrate private kernel data (bnc#1171220).

  - CVE-2020-10751: SELinux LSM hook implementation before
    version 5.7, where it incorrectly assumed that an skb
    would only contain a single netlink message. The hook
    would incorrectly only validate the first netlink
    message in the skb and allow or deny the rest of the
    messages within the skb with the granted permission
    without further processing (bnc#1171189).

  - CVE-2020-10766: Fixed rogue cross-process SSBD shutdown.
    Linux scheduler logical bug allowed an attacker to turn
    off the SSBD protection. (bnc#1172781).

  - CVE-2020-10767: Fixed that Indirect Branch Prediction
    Barrier is force-disabled when STIBP is unavailable or
    enhanced IBRS is available. (bnc#1172782).

  - CVE-2020-10768: Fixed that indirect branch speculation
    can be enabled after it was force-disabled by the
    PR_SPEC_FORCE_DISABLE prctl command (bnc#1172783).

  - CVE-2020-10773: Fixed a kernel stack information leak on
    s390/s390x. (bnc#1172999).

  - CVE-2020-12656: Fixed a memory leak in gss_mech_free in
    the rpcsec_gss_krb5 implementation due to lack of
    certain domain_release calls (bnc#1171219).

  - CVE-2020-12769: An issue was discovered in
    drivers/spi/spi-dw.c allowed attackers to cause a panic
    via concurrent calls to dw_spi_irq and
    dw_spi_transfer_one, aka CID-19b61392c5a8 (bnc#1171983).

  - CVE-2020-12888: The VFIO PCI driver mishandled attempts
    to access disabled memory space (bnc#1171868).

  - CVE-2020-13143: gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c relied on kstrdup without
    considering the possibility of an internal '\0' value,
    which allowed attackers to trigger an out-of-bounds
    read, aka CID-15753588bcd4 (bnc#1171982).

  - CVE-2020-13974: tty/vt/keyboard.c had an integer
    overflow if k_ascii is called several times in a row,
    aka CID-b86dab054059. (bnc#1172775).

  - CVE-2020-14416: A race condition in tty->disc_data
    handling in the slip and slcan line discipline could
    lead to a use-after-free, aka CID-0ace17d56824. This
    affects drivers/net/slip/slip.c and
    drivers/net/can/slcan.c (bnc#1162002).

The following non-security bugs were fixed :

  - ACPICA: Fixes for acpiExec namespace init file
    (git-fixes).

  - ACPI: CPPC: Fix reference count leak in
    acpi_cppc_processor_probe() (git-fixes).

  - ACPI: GED: add support for _Exx / _Lxx handler methods
    (git-fixes).

  - ACPI: GED: use correct trigger type field in _Exx / _Lxx
    handling (git-fixes).

  - ACPI: PM: Avoid using power resources if there are none
    for D0 (git-fixes).

  - ACPI: sysfs: Fix reference count leak in
    acpi_sysfs_add_hotplug_profile() (git-fixes).

  - af_unix: add compat_ioctl support (git-fixes).

  - agp/intel: Reinforce the barrier after GTT updates
    (git-fixes).

  - ALSA: emu10k1: delete an unnecessary condition
    (git-fixes).

  - ALSA: es1688: Add the missed snd_card_free()
    (git-fixes).

  - ALSA: fireface: fix configuration error for nominal
    sampling transfer frequency (git-fixes).

  - ALSA: firewire-lib: fix invalid assignment to union data
    for directional parameter (git-fixes).

  - ALSA: hda: Add ElkhartLake HDMI codec vid (git-fixes).

  - ALSA: hda: add member to store ratio for stripe control
    (git-fixes).

  - ALSA: hda: add sienna_cichlid audio asic id for
    sienna_cichlid up (git-fixes).

  - ALSA: hda: Fix potential race in unsol event handler
    (git-fixes).

  - ALSA: hda/realtek - Add a model for Thinkpad T570
    without DAC workaround (bsc#1172017).

  - ALSA: hda/realtek - add a pintbl quirk for several
    Lenovo machines (git-fixes).

  - ALSA: hda/realtek - Add LED class support for micmute
    LED (git-fixes).

  - ALSA: hda/realtek - Add more fixup entries for Clevo
    machines (git-fixes).

  - ALSA: hda/realtek - Add new codec supported for ALC287
    (git-fixes).

  - ALSA: hda/realtek - Enable micmute LED on and HP system
    (git-fixes).

  - ALSA: hda/realtek - Fix silent output on Gigabyte X570
    Aorus Xtreme (git-fixes).

  - ALSA: hda/realtek - Fix unused variable warning w/o
    CONFIG_LEDS_TRIGGER_AUDIO (git-fixes).

  - ALSA: hda/realtek - Introduce polarity for micmute LED
    GPIO (git-fixes).

  - ALSA: hda/tegra: correct number of SDO lines for
    Tegra194 (git-fixes).

  - ALSA: hda/tegra: workaround playback failure on Tegra194
    (git-fixes).

  - ALSA: hwdep: fix a left shifting 1 by 31 UB bug
    (git-fixes).

  - ALSA: iec1712: Initialize STDSP24 properly when using
    the model=staudio option (git-fixes).

  - ALSA: pcm: disallow linking stream to itself
    (git-fixes).

  - ALSA: pcm: fix incorrect hw_base increase (git-fixes).

  - ALSA: pcm: fix snd_pcm_link() lockdep splat (git-fixes).

  - ALSA: usb-audio: Add duplex sound support for USB
    devices using implicit feedback (git-fixes).

  - ALSA: usb-audio: Add Pioneer DJ DJM-900NXS2 support
    (git-fixes).

  - ALSA: usb-audio: Add vendor, product and profile name
    for HP Thunderbolt Dock (git-fixes).

  - ALSA: usb-audio: Clean up quirk entries with macros
    (git-fixes).

  - ALSA: usb-audio: Fix a limit check in
    proc_dump_substream_formats() (git-fixes).

  - ALSA: usb-audio: Fix inconsistent card PM state after
    resume (git-fixes).

  - ALSA: usb-audio: fixing upper volume limit for RME
    Babyface Pro routing crosspoints (git-fixes).

  - ALSA: usb-audio: Fixing usage of plain int instead of
    NULL (git-fixes).

  - ALSA: usb-audio: Fix racy list management in output
    queue (git-fixes).

  - ALSA: usb-audio: Improve frames size computation
    (git-fixes).

  - ALSA: usb-audio: Manage auto-pm of all bundled
    interfaces (git-fixes).

  - ALSA: usb-audio: mixer: volume quirk for ESS Technology
    Asus USB DAC (git-fixes).

  - ALSA: usb-audio: Print more information in stream proc
    files (git-fixes).

  - ALSA: usb-audio: Quirks for Gigabyte TRX40 Aorus Master
    onboard audio (git-fixes).

  - ALSA: usb-audio: Remove async workaround for Scarlett
    2nd gen (git-fixes).

  - ALSA: usb-audio: RME Babyface Pro mixer patch
    (git-fixes).

  - ALSA: usb-audio: Use the new macro for HP Dock rename
    quirks (git-fixes).

  - amd-xgbe: Use __napi_schedule() in BH context
    (networking-stable-20_04_17).

  - arm64: map FDT as RW for early_init_dt_scan()
    (jsc#SLE-12424).

  - ARM: oxnas: make ox820_boot_secondary static
    (git-fixes).

  - asm-gemeric/tlb: remove stray function declarations
    (bsc#1156395).

  - ASoC: fix incomplete error-handling in img_i2s_in_probe
    (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for Toshiba Encore
    WT10-A tablet (git-fixes).

  - ASoC: intel: cht_bsw_max98090_ti: Add all Chromebooks
    that need pmc_plt_clk_0 quirk (bsc#1171246).

  - ASoC: intel - fix the card names (git-fixes).

  - ASoC: max9867: fix volume controls (git-fixes).

  - ASoC: meson: add missing free_irq() in error path
    (git-fixes).

  - ASoC: rt5645: Add platform-data for Asus T101HA
    (git-fixes).

  - ASoC: SOF: core: fix error return code in
    sof_probe_continue() (git-fixes).

  - ASoC: ux500: mop500: Fix some refcounted resources
    issues (git-fixes).

  - ath10k: Remove ath10k_qmi_register_service_notifier()
    declaration (git-fixes).

  - ath10k: remove the max_sched_scan_reqs value
    (git-fixes).

  - ath10k: Skip handling del_server during driver exit
    (git-fixes).

  - ath9k: Fix general protection fault in
    ath9k_hif_usb_rx_cb (git-fixes).

  - ath9k: Fix use-after-free Read in ath9k_wmi_ctrl_rx
    (git-fixes).

  - ath9k: Fix use-after-free Read in htc_connect_service
    (git-fixes).

  - ath9k: Fix use-after-free Write in ath9k_htc_rx_msg
    (git-fixes).

  - ath9k_htc: Silence undersized packet warnings
    (git-fixes).

  - ath9x: Fix stack-out-of-bounds Write in
    ath9k_hif_usb_rx_cb (git-fixes).

  - ax25: fix setsockopt(SO_BINDTODEVICE) (git-fixes).

  - b43legacy: Fix case where channel status is corrupted
    (git-fixes).

  - bfq: Avoid false bfq queue merging (bsc#1171513).

  - bfq: Fix check detecting whether waker queue should be
    selected (bsc#1168838).

  - bfq: Use only idle IO periods for think time
    calculations (bsc#1171513).

  - bfq: Use 'ttime' local variable (bsc#1171513).

  - blk-iocost: Fix error on iocost_ioc_vrate_adj
    (bsc#1173206).

  - blk-iocost: fix incorrect vtime comparison in
    iocg_is_idle() (bsc#1173206).

  - bluetooth: btmtkuart: Improve exception handling in
    btmtuart_probe() (git-fixes).

  - bluetooth: hci_bcm: fix freeing not-requested IRQ
    (git-fixes).

  - bnxt_en: Improve TQM ring context memory sizing formulas
    (jsc#SLE-8371 bsc#1153274).

  - bpf: Fix map permissions check (bsc#1155518).

  - bpf: Prevent mmap()'ing read-only maps as writable
    (bsc#1155518).

  - bpf: Restrict bpf_probe_read(, str)() only to archs
    where they work (bsc#1172344).

  - bpf, sockhash: Synchronize_rcu before free'ing map
    (git-fixes).

  - bpf, sockmap: Check update requirements after locking
    (git-fixes).

  - bpf: Undo internal BPF_PROBE_MEM in BPF insns dump
    (bsc#1155518).

  - brcmfmac: fix wrong location to get firmware feature
    (git-fixes).

  - btrfs: fix log context list corruption after rename
    whiteout error (bsc#1172342).

  - btrfs: fix partial loss of prealloc extent past i_size
    after fsync (bsc#1172343).

  - btrfs: reloc: clear DEAD_RELOC_TREE bit for orphan roots
    to prevent runaway balance (bsc#1171417 bsc#1160947
    bsc#1172366).

  - btrfs: reloc: fix reloc root leak and NULL pointer
    dereference (bsc#1171417 bsc#1160947 bsc#1172366).

  - CDC-ACM: heed quirk also in error handling (git-fixes).

  - CDC-ACM: heed quirk also in error handling (git-fixes).

  - ceph: add comments for handle_cap_flush_ack logic
    (bsc#1172940).

  - ceph: allow rename operation under different quota
    realms (bsc#1172988).

  - ceph: ceph_kick_flushing_caps needs the s_mutex
    (bsc#1172986).

  - ceph: convert mdsc->cap_dirty to a per-session list
    (bsc#1172984 bsc#1167104).

  - ceph: document what protects i_dirty_item and
    i_flushing_item (bsc#1172940).

  - ceph: do not release i_ceph_lock in handle_cap_trunc
    (bsc#1172940).

  - ceph: do not return -ESTALE if there's still an open
    file (bsc#1171915).

  - ceph: do not take i_ceph_lock in handle_cap_import
    (bsc#1172940).

  - ceph: fix potential race in ceph_check_caps
    (bsc#1172940).

  - ceph: flush release queue when handling caps for unknown
    inode (bsc#1172939).

  - ceph: make sure mdsc->mutex is nested in s->s_mutex to
    fix dead lock (bsc#1172989).

  - ceph: normalize 'delta' parameter usage in
    check_quota_exceeded (bsc#1172987).

  - ceph: reorganize __send_cap for less spinlock abuse
    (bsc#1172940).

  - ceph: request expedited service on session's last cap
    flush (bsc#1172985 bsc#1167104).

  - ceph: reset i_requested_max_size if file write is not
    wanted (bsc#1172983).

  - ceph: skip checking caps when session reconnecting and
    releasing reqs (bsc#1172990).

  - ceph: split up __finish_cap_flush (bsc#1172940).

  - ceph: throw a warning if we destroy session with mutex
    still locked (bsc#1172940).

  - char/random: Add a newline at the end of the file
    (jsc#SLE-12424).

  - clk: bcm2835: Fix return type of bcm2835_register_gate
    (git-fixes).

  - clk: bcm2835: Remove casting to bcm2835_clk_register
    (git-fixes).

  - clk: clk-flexgen: fix clock-critical handling
    (git-fixes).

  - clk: mediatek: assign the initial value to clk_init_data
    of mtk_mux (git-fixes).

  - clk: meson: meson8b: Do not rely on u-boot to init all
    GP_PLL registers (git-fixes).

  - clk: meson: meson8b: Fix the polarity of the RESET_N
    lines (git-fixes).

  - clk: meson: meson8b: Fix the vclk_div(1, 2, 4, 6, 12)_en
    gate bits (git-fixes).

  - clk: qcom: Add missing msm8998 ufs_unipro_core_clk_src
    (git-fixes).

  - clk: renesas: cpg-mssr: Fix STBCR suspend/resume
    handling (git-fixes).

  - clk: samsung: Mark top ISP and CAM clocks on Exynos542x
    as critical (git-fixes).

  - clk: sprd: return correct type of value for
    _sprd_pll_recalc_rate (git-fixes).

  - clk: sunxi: Fix incorrect usage of round_down()
    (git-fixes).

  - clk: ti: am33xx: fix RTC clock parent (git-fixes).

  - clocksource: dw_apb_timer_of: Fix missing clockevent
    timers (git-fixes).

  - component: Silence bind error on -EPROBE_DEFER
    (git-fixes).

  - config: arm64: enable CONFIG_IOMMU_DEFAULT_PASSTHROUGH
    References: bsc#1172739

  - coredump: fix crash when umh is disabled (git-fixes).

  - coredump: fix NULL pointer dereference on coredump
    (git-fixes).

  - crypto: algapi - Avoid spurious modprobe on LOADED
    (git-fixes).

  - crypto: algboss - do not wait during notifier callback
    (git-fixes).

  - crypto: cavium/nitrox - Fix 'nitrox_get_first_device()'
    when ndevlist is fully iterated (git-fixes).

  - crypto: ccp -- do not 'select' CONFIG_DMADEVICES
    (git-fixes).

  - crypto: chelsio/chtls: properly set tp->lsndtime
    (git-fixes).

  - crypto: drbg - fix error return code in
    drbg_alloc_state() (git-fixes).

  - crypto: stm32/crc32 - fix ext4 chksum BUG_ON()
    (git-fixes).

  - crypto: stm32/crc32 - fix multi-instance (git-fixes).

  - crypto: stm32/crc32 - fix run-time self test issue
    (git-fixes).

  - cxgb4: fix adapter crash due to wrong MC size
    (networking-stable-20_04_27).

  - cxgb4: fix large delays in PTP synchronization
    (networking-stable-20_04_27).

  - Delete
    patches.suse/seltests-powerpc-Add-a-selftest-for-memcpy_
    mcsafe.patch (bsc#1171699).

  - dma-coherent: fix integer overflow in the
    reserved-memory dma allocation (git-fixes).

  - dma-debug: fix displaying of dma allocation type
    (git-fixes).

  - dma-direct: fix data truncation in
    dma_direct_get_required_mask() (git-fixes).

  - dmaengine: dmatest: Fix process hang when reading 'wait'
    parameter (git-fixes).

  - dmaengine: dmatest: Restore default for channel
    (git-fixes).

  - dmaengine: mmp_tdma: Do not ignore slave config
    validation errors (git-fixes).

  - dmaengine: mmp_tdma: Reset channel error on release
    (git-fixes).

  - dmaengine: owl: Use correct lock in owl_dma_get_pchan()
    (git-fixes).

  - dmaengine: pch_dma.c: Avoid data race between probe and
    irq handler (git-fixes).

  - dmaengine: tegra210-adma: Fix an error handling path in
    'tegra_adma_probe()' (git-fixes).

  - dm verity fec: fix hash block number in
    verity_fec_decode (git fixes (block drivers)).

  - dm writecache: fix data corruption when reloading the
    target (git fixes (block drivers)).

  - drivers/net/ibmvnic: Update VNIC protocol version
    reporting (bsc#1065729).

  - drivers: phy: sr-usb: do not use internal fsm for USB2
    phy init (git-fixes).

  - drivers: soc: ti: knav_qmss_queue: Make
    knav_gp_range_ops static (git-fixes).

  - drm/amd/display: add basic atomic check for cursor plane
    (git-fixes).

  - drm/amd/display: drop cursor position check in atomic
    test (git-fixes).

  - drm/amd/display: Prevent dpcd reads with passive dongles
    (git-fixes).

  - drm/amdgpu: force fbdev into vram (bsc#1152472) &#9;*
    context changes

  - drm/amdgpu: invalidate L2 before SDMA IBs (v2)
    (git-fixes).

  - drm/amdgpu: simplify padding calculations (v2)
    (git-fixes).

  - drm/amd/powerplay: avoid using pm_en before it is
    initialized revised (git-fixes).

  - drm/amd/powerplay: perform PG ungate prior to CG ungate
    (git-fixes).

  - drm/dp_mst: Increase ACT retry timeout to 3s
    (bsc#1152472) &#9;* context changes

  - drm/dp_mst: Reformat drm_dp_check_act_status() a bit
    (git-fixes).

  - drm/edid: Add Oculus Rift S to non-desktop list
    (git-fixes).

  - drm: encoder_slave: fix refcouting error for modules
    (git-fixes).

  - drm/etnaviv: fix perfmon domain interation (git-fixes).

  - drm/etnaviv: rework perfmon query infrastructure
    (git-fixes).

  - drm/i915: Do not enable WaIncreaseLatencyIPCEnabled when
    IPC is (bsc#1152489)

  - drm/i915: Do not enable WaIncreaseLatencyIPCEnabled when
    IPC is disabled (git-fixes).

  - drm/i915: extend audio CDCLK>=2*BCLK constraint to more
    platforms (git-fixes).

  - drm/i915: Extend WaDisableDARBFClkGating to icl,ehl,tgl
    (bsc#1152489)

  - drm/i915: fix port checks for MST support on gen >= 11
    (git-fixes).

  - drm/i915/gem: Avoid iterating an empty list (git-fixes).

  - drm/i915/gvt: Fix kernel oops for 3-level ppgtt guest
    (bsc#1152489)

  - drm/i915/gvt: Fix kernel oops for 3-level ppgtt guest
    (git-fixes).

  - drm/i915/gvt: Init DPLL/DDI vreg for virtual display
    instead of (bsc#1152489)

  - drm/i915/gvt: Init DPLL/DDI vreg for virtual display
    instead of inheritance (git-fixes).

  - drm/i915: HDCP: fix Ri prime check done during link
    check (bsc#1152489) &#9;* context changes

  - drm/i915: HDCP: fix Ri prime check done during link
    check (git-fixes).

  - drm/i915: Limit audio CDCLK>=2*BCLK constraint back to
    GLK only (git-fixes).

  - drm/i915: Propagate error from completed fences
    (git-fixes).

  - drm/i915: Whitelist context-local timestamp in the gen9
    cmdparser (git-fixes).

  - drm/i915: work around false-positive maybe-uninitialized
    warning (git-fixes).

  - drm/mcde: dsi: Fix return value check in mcde_dsi_bind()
    (git-fixes).

  - drm/qxl: lost qxl_bo_kunmap_atomic_page in
    qxl_image_init_helper() (git-fixes).

  - drm/sun4i: hdmi ddc clk: Fix size of m divider
    (git-fixes).

  - drm/vkms: Hold gem object while still in-use
    (git-fixes).

  - dwc3: Remove check for HWO flag in
    dwc3_gadget_ep_reclaim_trb_sg() (git-fixes).

  - e1000e: Disable TSO for buffer overrun workaround
    (git-fixes).

  - e1000e: Do not wake up the system via WOL if device
    wakeup is disabled (git-fixes).

  - EDAC/amd64: Add PCI device IDs for family 17h, model 70h
    (bsc#1165975).

  - EDAC/ghes: Setup DIMM label from DMI and use it in error
    reports (bsc#1168779).

  - EDAC/skx: Use the mcmtr register to retrieve
    close_pg/bank_xor_enable (bsc#1152489).

  - EDAC/synopsys: Do not dump uninitialized pinf->col
    (bsc#1152489).

  - efi/efivars: Add missing kobject_put() in sysfs entry
    creation error path (git-fixes).

  - efi/random: Treat EFI_RNG_PROTOCOL output as bootloader
    randomness (jsc#SLE-12424).

  - efi: READ_ONCE rng seed size before munmap
    (jsc#SLE-12424).

  - efi/tpm: Verify event log header before parsing
    (bsc#1173461).

  - eventpoll: fix missing wakeup for ovflist in
    ep_poll_callback (bsc#1159867).

  - evm: Check also if *tfm is an error pointer in
    init_desc() (git-fixes).

  - evm: Fix a small race in init_desc() (git-fixes).

  - evm: Fix possible memory leak in evm_calc_hmac_or_hash()
    (git-fixes).

  - evm: Fix RCU list related warnings (git-fixes).

  - extcon: adc-jack: Fix an error handling path in
    'adc_jack_probe()' (git-fixes).

  - fanotify: fix ignore mask logic for events on child and
    on dir (bsc#1172719).

  - fdt: add support for rng-seed (jsc#SLE-12424).

  - fdt: Update CRC check for rng-seed (jsc#SLE-12424).

  - firmware: imx: scu: Fix corruption of header
    (git-fixes).

  - firmware: imx: scu: Fix possible memory leak in
    imx_scu_probe() (git-fixes).

  - firmware: imx-scu: Support one TX and one RX
    (git-fixes).

  - firmware: imx: warn on unexpected RX (git-fixes).

  - firmware: qcom_scm: fix bogous abuse of dma-direct
    internals (git-fixes).

  - firmware: xilinx: Fix an error handling path in
    'zynqmp_firmware_probe()' (git-fixes).

  - Fix a regression of AF_ALG crypto interface hang with
    aes_s390 (bsc#1167651)

  - fpga: dfl: afu: Corrected error handling levels
    (git-fixes).

  - fs: Do not check if there is a fsnotify watcher on
    pseudo inodes (bsc#1158765).

  - fsnotify: Rearrange fast path to minimise overhead when
    there is no watcher (bsc#1158765).

  - genetlink: clean up family attributes allocations
    (git-fixes).

  - genetlink: fix memory leaks in
    genl_family_rcv_msg_dumpit() (bsc#1154353).

  - gpio: bcm-kona: Fix return value of
    bcm_kona_gpio_probe() (git-fixes).

  - gpio: dwapb: Append MODULE_ALIAS for platform driver
    (git-fixes).

  - gpio: dwapb: Call acpi_gpiochip_free_interrupts() on
    GPIO chip de-registration (git-fixes).

  - gpio: exar: Fix bad handling for ida_simple_get error
    path (git-fixes).

  - gpiolib: Document that GPIO line names are not globally
    unique (git-fixes).

  - gpio: pca953x: Fix pca953x_gpio_set_config (git-fixes).

  - gpio: pxa: Fix return value of pxa_gpio_probe()
    (git-fixes).

  - gpio: tegra: mask GPIO IRQs during IRQ shutdown
    (git-fixes).

  - gpu/drm: Ingenic: Fix opaque pointer casted to wrong
    type (git-fixes).

  - habanalabs: Align protection bits configuration of all
    TPCs (git-fixes).

  - HID: alps: Add AUI1657 device ID (git-fixes).

  - HID: alps: ALPS_1657 is too specific; use
    U1_UNICORN_LEGACY instead (git-fixes).

  - HID: i2c-hid: add Schneider SCL142ALM to descriptor
    override (git-fixes).

  - HID: i2c-hid: reset Synaptics SYNA2393 on resume
    (git-fixes).

  - HID: intel-ish-hid: avoid bogus uninitialized-variable
    warning (git-fixes).

  - HID: multitouch: add eGalaxTouch P80H84 support
    (git-fixes).

  - HID: multitouch: enable multi-input as a quirk for some
    devices (git-fixes).

  - HID: quirks: Add HID_QUIRK_NO_INIT_REPORTS quirk for
    Dell K12A keyboard-dock (git-fixes).

  - HID: sony: Fix for broken buttons on DS3 USB dongles
    (git-fixes).

  - hsr: check protocol version in hsr_newlink()
    (networking-stable-20_04_17).

  - i2c: acpi: put device when verifying client fails
    (git-fixes).

  - i2c: altera: Fix race between xfer_msg and isr thread
    (git-fixes).

  - i2c: designware-pci: Add support for Elkhart Lake PSE
    I2C (jsc#SLE-12734).

  - i2c: designware-pci: Fix BUG_ON during device removal
    (jsc#SLE-12734).

  - i2c: designware-pci: Switch over to MSI interrupts
    (jsc#SLE-12734).

  - i2c: dev: Fix the race between the release of i2c_dev
    and cdev (git-fixes).

  - i2c: fix missing pm_runtime_put_sync in i2c_device_probe
    (git-fixes).

  - i2c: mux: demux-pinctrl: Fix an error handling path in
    'i2c_demux_pinctrl_probe()' (git-fixes).

  - ibmveth: Fix max MTU limit (bsc#1173428 ltc#186397).

  - ibmvnic: continue to init in CRQ reset returns H_CLOSED
    (bsc#1173280 ltc#185369).

  - ibmvnic: Flush existing work items before device removal
    (bsc#1065729).

  - ibmvnic: Harden device login requests (bsc#1170011
    ltc#183538).

  - ice: Fix error return code in ice_add_prof()
    (jsc#SLE-7926).

  - ice: Fix inability to set channels when down
    (jsc#SLE-7926).

  - ieee80211: Fix incorrect mask for default PE duration
    (git-fixes).

  - iio: adc: stm32-adc: fix device used to request dma
    (git-fixes).

  - iio: adc: stm32-adc: Use dma_request_chan() instead
    dma_request_slave_channel() (git-fixes).

  - iio: adc: stm32-dfsdm: fix device used to request dma
    (git-fixes).

  - iio: adc: stm32-dfsdm: Use dma_request_chan() instead
    dma_request_slave_channel() (git-fixes).

  - iio: adc: ti-ads8344: Fix channel selection (git-fixes).

  - iio: buffer: Do not allow buffers without any channels
    enabled to be activated (git-fixes).

  - iio:chemical:pms7003: Fix timestamp alignment and
    prevent data leak (git-fixes).

  - iio:chemical:sps30: Fix timestamp alignment (git-fixes).

  - iio: dac: vf610: Fix an error handling path in
    'vf610_dac_probe()' (git-fixes).

  - iio: pressure: bmp280: Tolerate IRQ before registering
    (git-fixes).

  - iio: sca3000: Remove an erroneous 'get_device()'
    (git-fixes).

  - iio: vcnl4000: Fix i2c swapped word reading (git-fixes).

  - ima: Call ima_calc_boot_aggregate() in
    ima_eventdigest_init() (bsc#1172223).

  - ima: Directly assign the ima_default_policy pointer to
    ima_rules (bsc#1172223)

  - ima: Directly free *entry in ima_alloc_init_template()
    if digests is NULL (bsc#1172223).

  - ima: Remove __init annotation from ima_pcrread()
    (git-fixes).

  - include/asm-generic/topology.h: guard cpumask_of_node()
    macro argument (bsc#1148868).

  - Input: dlink-dir685-touchkeys - fix a typo in driver
    name (git-fixes).

  - Input: edt-ft5x06 - fix get_default register write
    access (git-fixes).

  - Input: evdev - call input_flush_device() on release(),
    not flush() (git-fixes).

  - Input: i8042 - add ThinkPad S230u to i8042 reset list
    (git-fixes).

  - Input: mms114 - fix handling of mms345l (git-fixes).

  - Input: synaptics - add a second working PNP_ID for
    Lenovo T470s (git-fixes).

  - Input: synaptics-rmi4 - fix error return code in
    rmi_driver_probe() (git-fixes).

  - Input: synaptics-rmi4 - really fix attn_data
    use-after-free (git-fixes).

  - Input: usbtouchscreen - add support for BonXeon TP
    (git-fixes).

  - Input: xpad - add custom init packet for Xbox One S
    controllers (git-fixes).

  - iocost: check active_list of all the ancestors in
    iocg_activate() (bsc#1173206).

  - iocost: do not let vrate run wild while there's no
    saturation signal (bsc1173206).

  - iocost: over-budget forced IOs should schedule async
    delay (bsc#1173206).

  - iommu/amd: Call domain_flush_complete() in
    update_domain() (bsc#1172061).

  - iommu/amd: Do not flush Device Table in iommu_map_page()
    (bsc#1172062).

  - iommu/amd: Do not loop forever when trying to increase
    address space (bsc#1172063).

  - iommu/amd: Fix legacy interrupt remapping for
    x2APIC-enabled system (bsc#1172393).

  - iommu/amd: Fix over-read of ACPI UID from IVRS table
    (bsc#1172064).

  - iommu/amd: Fix race in
    increase_address_space()/fetch_pte() (bsc#1172065).

  - iommu/amd: Update Device Table in
    increase_address_space() (bsc#1172066).

  - iommu: Fix reference count leak in iommu_group_alloc
    (bsc#1172394).

  - iommu/qcom: Fix local_base status check (bsc#1172067).

  - iommu/virtio: Reverse arguments to list_add
    (bsc#1172068).

  - ipv4: Update fib_select_default to handle nexthop
    objects (networking-stable-20_04_27).

  - ipv6: fix IPV6_ADDRFORM operation logic (bsc#1171662).

  - ipvs: Improve robustness to the ipvs sysctl (git-fixes).

  - irqchip/al-fic: Add support for irq retrigger
    (jsc#SLE-10505).

  - irqchip/ti-sci-inta: Fix processing of masked irqs
    (git-fixes).

  - irqchip/versatile-fpga: Apply clear-mask earlier
    (git-fixes).

  - irqchip/versatile-fpga: Handle chained IRQs properly
    (git-fixes).

  - iwlwifi: avoid debug max amsdu config overwriting itself
    (git-fixes).

  - iwlwifi: mvm: limit maximum queue appropriately
    (git-fixes).

  - iwlwifi: pcie: handle QuZ configs with killer NICs as
    well (bsc#1172374).

  - jbd2: fix data races at struct journal_head
    (bsc#1173438).

  - kabi: ppc64le: prevent struct dma_map_ops to become
    defined (jsc#SLE-12424).

  - kabi/severities: Ingnore get_dev_data() The function is
    internal to the AMD IOMMU driver and must not be called
    by any third-party.

  - kABI workaround for struct hdac_bus changes (git-fixes).

  - ktest: Add timeout for ssh sync testing (git-fixes).

  - KVM: Check validity of resolved slot when searching
    memslots (bsc#1172069).

  - KVM: x86/mmu: Set mmio_value to '0' if reserved #PF
    can't be generated (bsc#1171904).

  - KVM: x86: only do L1TF workaround on affected processors
    (bsc#1171904).

  - l2tp: Allow management of tunnels and session in user
    namespace (networking-stable-20_04_17).

  - libbpf: Fix perf_buffer__free() API for sparse allocs
    (bsc#1155518).

  - libceph: ignore pool overlay and cache logic on
    redirects (bsc#1172938).

  - lib: devres: add a helper function for ioremap_uc
    (git-fixes).

  - libertas_tf: avoid a null dereference in pointer priv
    (git-fixes).

  - lib/lzo: fix ambiguous encoding bug in lzo-rle
    (git-fixes).

  - libnvdimm/btt: fix variable 'rc' set but not used
    (bsc#1162400).

  - libnvdimm: cover up nd_pfn_sb changes (bsc#1171759).

  - libnvdimm: cover up nd_region changes (bsc#1162400).

  - libnvdimm/dax: Pick the right alignment default when
    creating dax devices (bsc#1171759).

  - libnvdimm/label: Remove the dpa align check
    (bsc#1171759).

  - libnvdimm/namespace: Enforce memremap_compat_align()
    (bsc#1162400).

  - libnvdimm/namsepace: Do not set claim_class on error
    (bsc#1162400).

  - libnvdimm/of_pmem: Provide a unique name for bus
    provider (bsc#1171739).

  - libnvdimm: Out of bounds read in __nd_ioctl()
    (bsc#1065729).

  - libnvdimm/pfn_dev: Add a build check to make sure we
    notice when struct page size change (bsc#1171743).

  - libnvdimm/pfn_dev: Add page size and struct page size to
    pfn superblock (bsc#1171759).

  - libnvdimm/pfn: Prevent raw mode fallback if
    pfn-infoblock valid (bsc#1171743).

  - libnvdimm/pmem: Advance namespace seed for specific
    probe errors (bsc#1171743).

  - libnvdimm/region: Fix build error (bsc#1162400).

  - libnvdimm/region: Introduce an 'align' attribute
    (bsc#1162400).

  - libnvdimm/region: Introduce NDD_LABELING (bsc#1162400).

  - libnvdimm/region: Rewrite _probe_success() to
    _advance_seeds() (bsc#1171743).

  - libnvdimm: Use PAGE_SIZE instead of SZ_4K for align
    check (bsc#1171759).

  - lib: Uplevel the pmem 'region' ida to a global allocator
    (bc#1162400).

  - list: Add hlist_unhashed_lockless() (bsc#1173438).

  - livepatch: Apply vmlinux-specific KLP relocations early
    (bsc#1071995).

  - livepatch: Disallow vmlinux.ko (bsc#1071995).

  - livepatch: Make klp_apply_object_relocs static
    (bsc#1071995).

  - livepatch: Prevent module-specific KLP rela sections
    from referencing vmlinux symbols (bsc#1071995).

  - livepatch: Remove .klp.arch (bsc#1071995).

  - locktorture: Allow CPU-hotplug to be disabled via
    --bootargs (bsc#1173068).

  - lpfc_debugfs: get rid of pointless access_ok()
    (bsc#1171530).

  - lpfc: fix axchg pointer reference after free and double
    frees (bsc#1171530).

  - lpfc: Fix pointer checks and comments in LS receive
    refactoring (bsc#1171530).

  - lpfc: Fix return value in __lpfc_nvme_ls_abort
    (bsc#1171530).

  - lpfc: Synchronize NVME transport and lpfc driver
    devloss_tmo (bcs#1173060).

  - mac80211: mesh: fix discovery timer re-arming issue /
    crash (git-fixes).

  - mailbox: zynqmp-ipi: Fix NULL vs IS_ERR() check in
    zynqmp_ipi_mbox_probe() (git-fixes).

  - Make the 'Reducing compressed framebufer size' message
    be DRM_INFO_ONCE() (git-fixes).

  - mdraid: fix read/write bytes accounting (bsc#1172537).

  - media: cedrus: Program output format during each run
    (git-fixes).

  - media: dvb: return -EREMOTEIO on i2c transfer failure
    (git-fixes).

  - media: platform: fcp: Set appropriate DMA parameters
    (git-fixes).

  - media: Revert 'staging: imgu: Address a compiler warning
    on alignment' (git-fixes).

  - media: staging: ipu3: Fix stale list entries on
    parameter queue failure (git-fixes).

  - media: staging: ipu3-imgu: Move alignment attribute to
    field (git-fixes).

  - mei: release me_cl object reference (git-fixes).

  - mfd: intel-lpss: Add Intel Tiger Lake PCI IDs
    (jsc#SLE-12737).

  - mfd: intel-lpss: Use devm_ioremap_uc for MMIO
    (git-fixes).

  - mfd: stmfx: Fix stmfx_irq_init error path (git-fixes).

  - mfd: stmfx: Reset chip on resume as supply was disabled
    (git-fixes).

  - misc: fastrpc: fix potential fastrpc_invoke_ctx leak
    (git-fixes).

  - misc: rtsx: Add short delay after exit from ASPM
    (git-fixes).

  - mlxsw: Fix some IS_ERR() vs NULL bugs
    (networking-stable-20_04_27).

  - mm: adjust vm_committed_as_batch according to vm
    overcommit policy (bnc#1173271).

  - mmc: block: Fix use-after-free issue for rpmb
    (git-fixes).

  - mmc: core: Use DEFINE_DEBUGFS_ATTRIBUTE instead of
    DEFINE_SIMPLE_ATTRIBUTE (git-fixes).

  - mmc: fix compilation of user API (git-fixes).

  - mmc: meson-mx-sdio: trigger a soft reset after a timeout
    or CRC error (git-fixes).

  - mmc: mmci_sdmmc: fix DMA API warning overlapping
    mappings (git-fixes).

  - mmc: sdhci-esdhc-imx: fix the mask for tuning start
    point (git-fixes).

  - mmc: sdhci-msm: Clear tuning done flag while hs400
    tuning (git-fixes).

  - mmc: sdio: Fix potential NULL pointer error in
    mmc_sdio_init_card() (git-fixes).

  - mmc: sdio: Fix several potential memory leaks in
    mmc_sdio_init_card() (git-fixes).

  - mmc: tmio: Further fixup runtime PM management at remove
    (git-fixes).

  - mmc: uniphier-sd: call devm_request_irq() after
    tmio_mmc_host_probe() (git-fixes).

  - mm: do not prepare anon_vma if vma has VM_WIPEONFORK
    (bsc#1169681).

  - mm: memcontrol: fix memory.low proportional distribution
    (bsc#1168230).

  - mm/memremap: drop unused SECTION_SIZE and SECTION_MASK
    (bsc#1162400 bsc#1170895 ltc#184375 ltc#185686).

  - mm/memremap_pages: Introduce memremap_compat_align()
    (bsc#1162400).

  - mm/memremap_pages: Kill unused __devm_memremap_pages()
    (bsc#1162400).

  - mm/util.c: make vm_memory_committed() more accurate
    (bnc#1173271).

  - mt76: mt76x02u: Add support for newer versions of the
    XBox One wifi adapter (git-fixes).

  - mtd: Fix mtd not registered due to nvmem name collision
    (git-fixes).

  - mtd: rawnand: brcmnand: correctly verify erased pages
    (git-fixes).

  - mtd: rawnand: brcmnand: fix CS0 layout (git-fixes).

  - mtd: rawnand: brcmnand: fix hamming oob layout
    (git-fixes).

  - mtd: rawnand: diskonchip: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: Fix nand_gpio_waitrdy() (git-fixes).

  - mtd: rawnand: ingenic: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: marvell: Fix probe error path (git-fixes).

  - mtd: rawnand: marvell: Fix the condition on a return
    code (git-fixes).

  - mtd: rawnand: marvell: Use nand_cleanup() when the
    device is not yet registered (git-fixes).

  - mtd: rawnand: mtk: Fix the probe error path (git-fixes).

  - mtd: rawnand: onfi: Fix redundancy detection check
    (git-fixes).

  - mtd: rawnand: orion: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: oxnas: Keep track of registered devices
    (git-fixes).

  - mtd: rawnand: oxnas: Release all devices in the
    _remove() path (git-fixes).

  - mtd: rawnand: pasemi: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: plat_nand: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: sharpsl: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: socrates: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: sunxi: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: timings: Fix default tR_max and tCCS_min
    timings (git-fixes).

  - mtd: rawnand: tmio: Fix the probe error path
    (git-fixes).

  - mtd: rawnand: xway: Fix the probe error path
    (git-fixes).

  - mtd: spinand: Propagate ECC information to the MTD
    structure (git-fixes).

  - mtd: spi-nor: intel-spi: Add support for Intel Tiger
    Lake SPI serial flash (jsc#SLE-12737).

  - mwifiex: avoid -Wstringop-overflow warning (git-fixes).

  - mwifiex: Fix memory corruption in dump_station
    (git-fixes).

  - net: bcmgenet: correct per TX/RX ring statistics
    (networking-stable-20_04_27).

  - net: dsa: b53: b53_arl_rw_op() needs to select IVL or
    SVL (networking-stable-20_04_27).

  - net: dsa: b53: Fix ARL register definitions
    (networking-stable-20_04_27).

  - net: dsa: b53: Lookup VID in ARL searches when VLAN is
    enabled (networking-stable-20_04_27).

  - net: dsa: b53: Rework ARL bin logic
    (networking-stable-20_04_27).

  - net: dsa: declare lockless TX feature for slave ports
    (bsc#1154353).

  - net: dsa: mt7530: fix tagged frames pass-through in
    VLAN-unaware mode (networking-stable-20_04_17).

  - net: ena: xdp: update napi budget for DROP and ABORTED
    (bsc#1154492).

  - net: ena: xdp: XDP_TX: fix memory leak (bsc#1154492).

  - netfilter: connlabels: prefer static lock initialiser
    (git-fixes).

  - netfilter: nf_queue: enqueue skbs with NULL dst
    (git-fixes).

  - netfilter: nf_tables_offload: return EOPNOTSUPP if rule
    specifies no actions (git-fixes).

  - netfilter: nft_tproxy: Fix port selector on Big Endian
    (git-fixes).

  - netfilter: nft_tunnel: add the missing ERSPAN_VERSION
    nla_policy (git-fixes).

  - netfilter: not mark a spinlock as __read_mostly
    (git-fixes).

  - net: ipv4: devinet: Fix crash when add/del multicast IP
    with autojoin (networking-stable-20_04_17).

  - net: ipv6: do not consider routes via gateways for
    anycast address check (networking-stable-20_04_17).

  - net/mlx4_en: avoid indirect call in TX completion
    (networking-stable-20_04_27).

  - net/mlx5e: Add missing release firmware call
    (networking-stable-20_04_17).

  - net/mlx5e: Fix pfnum in devlink port attribute
    (networking-stable-20_04_17).

  - net/mlx5e: Fix stats update for matchall classifier
    (jsc#SLE-8464).

  - net/mlx5e: replace EINVAL in mlx5e_flower_parse_meta()
    (jsc#SLE-8464).

  - net/mlx5: Fix cleaning unmanaged flow tables
    (jsc#SLE-8464).

  - net/mlx5: Fix crash upon suspend/resume (bsc#1172365).

  - net/mlx5: Fix frequent ioread PCI access during recovery
    (networking-stable-20_04_17).

  - net: netrom: Fix potential nr_neigh refcnt leak in
    nr_add_node (networking-stable-20_04_27).

  - net: openvswitch: ovs_ct_exit to be done under ovs_lock
    (networking-stable-20_04_27).

  - net: phy: propagate an error back to the callers of
    phy_sfp_probe (bsc#1154353).

  - net: qrtr: send msgs from local of same id as broadcast
    (networking-stable-20_04_17).

  - net: revert default NAPI poll timeout to 2 jiffies
    (networking-stable-20_04_17).

  - net: revert 'net: get rid of an signed integer overflow
    in ip_idents_reserve()' (bnc#1158748 (network
    regression)).

  - net: tun: record RX queue in skb before do_xdp_generic()
    (networking-stable-20_04_17).

  - net: vmxnet3: fix possible buffer overflow caused by bad
    DMA value in vmxnet3_get_rss() (bsc#1172484).

  - net/x25: Fix x25_neigh refcnt leak when receiving frame
    (networking-stable-20_04_27).

  - NFC: st21nfca: add missed kfree_skb() in an error path
    (git-fixes).

  - nfs: add minor version to nfs_server_key for fscache
    (bsc#1172467).

  - nfsd4: make drc_slab global, not per-net (git-fixes).

  - nfsd: always check return value of find_any_file
    (bsc#1172208).

  - NFS: Fix fscache super_cookie index_key from changing
    after umount (git-fixes).

  - nfs: fix NULL deference in nfs4_get_valid_delegation.

  - nfs: fscache: use timespec64 in inode auxdata
    (git-fixes).

  - nfs: set invalid blocks after NFSv4 writes (git-fixes).

  - NFSv4.1 fix rpc_call_done assignment for
    BIND_CONN_TO_SESSION (git-fixes).

  - NFSv4: Fix fscache cookie aux_data to ensure change_attr
    is included (git-fixes).

  - ntb: intel: add hw workaround for NTB BAR alignment
    (jsc#SLE-12710).

  - ntb: intel: Add Icelake (gen4) support for Intel NTB
    (jsc#SLE-12710).

  - ntb: intel: fix static declaration (jsc#SLE-12710).

  - nvdimm: Avoid race between probe and reading device
    attributes (bsc#1170442).

  - nvme-fc: avoid gcc-10 zero-length-bounds warning
    (bsc#1173206).

  - nvme-fc: do not call nvme_cleanup_cmd() for AENs
    (bsc#1171688).

  - nvme-fc: print proper nvme-fc devloss_tmo value
    (bsc#1172391).

  - objtool: Allow no-op CFI ops in alternatives
    (bsc#1169514).

  - objtool: Clean instruction state before each function
    validation (bsc#1169514).

  - objtool: Fix !CFI insn_state propagation (bsc#1169514).

  - objtool: Fix ORC vs alternatives (bsc#1169514).

  - objtool: Ignore empty alternatives (bsc#1169514).

  - objtool: Remove check preventing branches within
    alternative (bsc#1169514).

  - objtool: Rename struct cfi_state (bsc#1169514).

  - objtool: Uniquely identify alternative instruction
    groups (bsc#1169514).

  - p54usb: add AirVasT USB stick device-id (git-fixes).

  - panic: do not print uninitialized taint_flags
    (bsc#1172814).

  - PCI: Allow pci_resize_resource() for devices on root bus
    (git-fixes).

  - PCI: amlogic: meson: Do not use FAST_LINK_MODE to set up
    link (git-fixes).

  - PCI: brcmstb: Assert fundamental reset on initialization
    (git-fixes).

  - PCI: brcmstb: Assert fundamental reset on initialization
    (git-fixes).

  - PCI: brcmstb: Fix window register offset from 4 to 8
    (git-fixes).

  - PCI: brcmstb: Fix window register offset from 4 to 8
    (git-fixes).

  - pcie: mobiveil: remove patchset v9 Prepare to backport
    upstream version.

  - PCI: Fix pci_register_host_bridge() device_register()
    error handling (git-fixes).

  - PCI: mobiveil: Add 8-bit and 16-bit CSR register
    accessors (bsc#1161495).

  - PCI: mobiveil: Add callback function for interrupt
    initialization (bsc#1161495).

  - PCI: mobiveil: Add callback function for link up check
    (bsc#1161495).

  - PCI: mobiveil: Add Header Type field check
    (bsc#1161495).

  - PCI: mobiveil: Add PCIe Gen4 RC driver for Layerscape
    SoCs (bsc#1161495).

  - PCI: mobiveil: Allow mobiveil_host_init() to be used to
    re-init host (bsc#1161495).

  - PCI: mobiveil: Collect the interrupt related operations
    into a function (bsc#1161495).

  - PCI: mobiveil: Fix sparse different address space
    warnings (bsc#1161495).

  - PCI: mobiveil: Fix unmet dependency warning for
    PCIE_MOBIVEIL_PLAT (bsc#1161495).

  - PCI: mobiveil: Introduce a new structure
    mobiveil_root_port (bsc#1161495).

  - PCI: mobiveil: ls_pcie_g4: add Workaround for A-011451
    (bsc#1161495).

  - PCI: mobiveil: ls_pcie_g4: add Workaround for A-011577
    (bsc#1161495).

  - PCI: mobiveil: ls_pcie_g4: fix SError when accessing
    config space (bsc#1161495).

  - PCI: mobiveil: Modularize the Mobiveil PCIe Host Bridge
    IP driver (bsc#1161495).

  - PCI: mobiveil: Move the host initialization into a
    function (bsc#1161495).

  - PCI/PM: Adjust pcie_wait_for_link_delay() for caller
    delay (git-fixes).

  - PCI/PM: Call .bridge_d3() hook only if non-NULL
    (git-fixes).

  - PCI: Program MPS for RCiEP devices (git-fixes).

  - PCI/PTM: Inherit Switch Downstream Port PTM settings
    from Upstream Port (git-fixes).

  - PCI: rcar: Fix incorrect programming of OB windows
    (git-fixes).

  - PCI: v3-semi: Fix a memory leak in v3_pci_probe() error
    handling paths (git-fixes).

  - PCI: vmd: Filter resource type bits from shadow register
    (git-fixes).

  - pcm_native: result of put_user() needs to be checked
    (git-fixes).

  - perf/core: Fix endless multiplex timer (git-fixes).

  - perf/core: fix parent pid/tid in task exit events
    (git-fixes).

  - pinctrl: freescale: imx: Fix an error handling path in
    'imx_pinctrl_probe()' (git-fixes).

  - pinctrl: freescale: imx: Use 'devm_of_iomap()' to avoid
    a resource leak in case of error in
    'imx_pinctrl_probe()' (git-fixes).

  - pinctrl: imxl: Fix an error handling path in
    'imx1_pinctrl_core_probe()' (git-fixes).

  - pinctrl: intel: Add Intel Tiger Lake pin controller
    support (jsc#SLE-12737).

  - pinctrl: ocelot: Fix GPIO interrupt decoding on Jaguar2
    (git-fixes).

  - pinctrl: rza1: Fix wrong array assignment of
    rza1l_swio_entries (git-fixes).

  - pinctrl: samsung: Correct setting of eint wakeup mask on
    s5pv210 (git-fixes).

  - pinctrl: samsung: Save/restore eint_mask over suspend
    for EINT_TYPE GPIOs (git-fixes).

  - pinctrl: sprd: Fix the incorrect pull-up definition
    (git-fixes).

  - pinctrl: stmfx: stmfx_pinconf_set does not require to
    get direction anymore (git-fixes).

  - pinctrl: tigerlake: Tiger Lake uses _HID enumeration
    (jsc#SLE-12737).

  - platform/x86: asus-nb-wmi: Do not load on Asus T100TA
    and T200TA (git-fixes).

  - platform/x86: dell-laptop: do not register micmute LED
    if there is no token (git-fixes).

  - platform/x86: intel-vbtn: Also handle tablet-mode switch
    on 'Detachable' and 'Portable' chassis-types
    (git-fixes).

  - platform/x86: intel-vbtn: Do not advertise switches to
    userspace if they are not there (git-fixes).

  - platform/x86: intel-vbtn: Only blacklist SW_TABLET_MODE
    on the 9 / 'Laptop' chasis-type (git-fixes).

  - platform/x86: intel-vbtn: Split keymap into buttons and
    switches parts (git-fixes).

  - platform/x86: intel-vbtn: Use acpi_evaluate_integer()
    (git-fixes).

  - PM: runtime: clk: Fix clk_pm_runtime_get() error path
    (git-fixes).

  - pnp: Use list_for_each_entry() instead of open coding
    (git-fixes).

  - powerpc/64s: Do not let DT CPU features set FSCR_DSCR
    (bsc#1065729).

  - powerpc/64s/exception: Fix machine check no-loss idle
    wakeup (bsc#1156395).

  - powerpc/64s/kuap: Restore AMR in system reset exception
    (bsc#1156395).

  - powerpc/64s: Save FSCR to init_task.thread.fscr after
    feature init (bsc#1065729).

  - powerpc/book3s64: Export has_transparent_hugepage()
    related functions (bsc#1171759).

  - powerpc/bpf: Enable bpf_probe_read(, str)() on powerpc
    again (bsc#1172344).

  - powerpc/fadump: Account for memory_limit while reserving
    memory (jsc#SLE-9099 git-fixes).

  - powerpc/fadump: consider reserved ranges while reserving
    memory (jsc#SLE-9099 git-fixes).

  - powerpc/fadump: use static allocation for reserved
    memory ranges (jsc#SLE-9099 git-fixes).

  - powerpc/kuap: PPC_KUAP_DEBUG should depend on PPC_KUAP
    (bsc#1156395).

  - powerpc/powernv: Fix a warning message (bsc#1156395).

  - powerpc/setup_64: Set cache-line-size based on
    cache-block-size (bsc#1065729).

  - powerpc/xive: Clear the page tables for the ESB IO
    mapping (bsc#1085030).

  - power: reset: qcom-pon: reg write mask depends on pon
    generation (git-fixes).

  - power: supply: bq24257_charger: Replace depends on
    REGMAP_I2C with select (git-fixes).

  - power: supply: core: fix HWMON temperature labels
    (git-fixes).

  - power: supply: core: fix memory leak in HWMON error path
    (git-fixes).

  - power: supply: lp8788: Fix an error handling path in
    'lp8788_charger_probe()' (git-fixes).

  - power: supply: smb347-charger: IRQSTAT_D is volatile
    (git-fixes).

  - printk: queue wake_up_klogd irq_work only if per-CPU
    areas are ready (bsc#1172095).

  - proc/meminfo: avoid open coded reading of
    vm_committed_as (bnc#1173271).

  - pwm: sun4i: Move pwm_calculate() out of spin_lock()
    (git-fixes).

  - r8152: support additional Microsoft Surface Ethernet
    Adapter variant (git-fixes).

  - r8169: Revive default chip version for r8168
    (bsc#1173085).

  - raid5: remove gfp flags from scribble_alloc()
    (bsc#1166985).

  - random: fix data races at timer_rand_state
    (bsc#1173438).

  - rcu: Avoid data-race in rcu_gp_fqs_check_wake()
    (bsc#1171828).

  - rcu: Fix data-race due to atomic_t copy-by-value
    (bsc#1171828).

  - rcu: Make rcu_read_unlock_special() checks match
    raise_softirq_irqoff() (bsc#1172046).

  - rcu: Simplify rcu_read_unlock_special() deferred wakeups
    (bsc#1172046).

  - rcutorture: Add 100-CPU configuration (bsc#1173068).

  - rcutorture: Add worst-case call_rcu() forward-progress
    results (bsc#1173068).

  - rcutorture: Dispense with Dracut for initrd creation
    (bsc#1173068).

  - rcutorture: Make kvm-find-errors.sh abort on bad
    directory (bsc#1173068).

  - rcutorture: Remove CONFIG_HOTPLUG_CPU=n from scenarios
    (bsc#1173068).

  - rcutorture: Summarize summary of build and run results
    (bsc#1173068).

  - rcutorture: Test TREE03 with the threadirqs kernel boot
    parameter (bsc#1173068).

  - rcu: Use *_ONCE() to protect lockless ->expmask accesses
    (bsc#1171828).

  - rcu: Use WRITE_ONCE() for assignments to ->pprev for
    hlist_nulls (bsc#1173438).

  - RDMA/bnxt_re: Remove dead code from rcfw (bsc#1170774).

  - RDMA/core: Move and rename trace_cm_id_create()
    (jsc#SLE-8449).

  - RDMA/mlx5: Fix NULL pointer dereference in
    destroy_prefetch_work (jsc#SLE-8446).

  - RDMA/nl: Do not permit empty devices names during
    RDMA_NLDEV_CMD_NEWLINK/SET (bsc#1172841).

  - RDMA/srpt: Fix disabling device management
    (jsc#SLE-8449).

  - RDMA/uverbs: Make the event_queue fds return POLLERR
    when disassociated (jsc#SLE-8449).

  - remoteproc: Add missing '\n' in log messages
    (git-fixes).

  - remoteproc: Fall back to using parent memory pool if no
    dedicated available (git-fixes).

  - remoteproc: Fix and restore the parenting hierarchy for
    vdev (git-fixes).

  - remoteproc: Fix IDR initialisation in rproc_alloc()
    (git-fixes).

  - Revert 'drm/amd/display: disable dcn20 abm feature for
    bring up' (git-fixes).

  - Revert 'fs/seq_file.c: seq_read(): add info message
    about buggy .next functions' (bsc#1172751) The message
    floods dmesg and its benefit is marginal in default
    kernel.

  - Revert 'pinctrl: freescale: imx: Use 'devm_of_iomap()'
    to avoid a resource leak in case of error in
    'imx_pinctrl_probe()'' (git-fixes).

  - rpm/kernel-source.spec.in: Add obsolete_rebuilds
    (boo#1172073).

  - rpm/modules.fips: * add aes-ce-ccm and des3_ede-x86_64
    (boo#173030) * add aes_ti and aes_neon_bs (boo#1172956)

  - rtc: mc13xxx: fix a double-unlock issue (git-fixes).

  - rtc: rv3028: Add missed check for devm_regmap_init_i2c()
    (git-fixes).

  - rtlwifi: Fix a double free in _rtl_usb_tx_urb_setup()
    (git-fixes).

  - rtw88: fix an issue about leak system resources
    (git-fixes).

  - rxrpc: Fix call RCU cleanup using non-bh-safe locks
    (git-fixes).

  - s390/bpf: Maintain 8-byte stack alignment (bsc#1169194,
    LTC#185911).

  - s390/pci: Log new handle in clp_disable_fh()
    (git-fixes).

  - sched/cfs: change initial value of runnable_avg
    (bsc#1158765).

  - sched/core: Check cpus_mask, not cpus_ptr in
    __set_cpus_allowed_ptr(), to fix mask corruption
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched/core: Fix PI boosting between RT and DEADLINE
    tasks (bsc#1172823).

  - sched/core: Fix PI boosting between RT and DEADLINE
    tasks (git fixes (sched)).

  - sched/core: Fix ttwu() race (bnc#1155798 (CPU scheduler
    functional and performance backports)).

  - sched/core: s/WF_ON_RQ/WQ_ON_CPU/ (bnc#1155798 (CPU
    scheduler functional and performance backports)).

  - sched/cpuacct: Fix charge cpuacct.usage_sys (bnc#1155798
    (CPU scheduler functional and performance backports)).

  - sched/deadline: Initialize ->dl_boosted (bsc#1172823).

  - sched/deadline: Initialize ->dl_boosted (git fixes
    (sched)).

  - sched: etf: do not assume all sockets are full blown
    (networking-stable-20_04_27).

  - sched/fair: find_idlest_group(): Remove unused sd_flag
    parameter (bnc#1155798 (CPU scheduler functional and
    performance backports)).

  - sched/fair: Fix enqueue_task_fair() warning some more
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched/fair: fix nohz next idle balance (bnc#1155798 (CPU
    scheduler functional and performance backports)).

  - sched/fair: Optimize dequeue_task_fair() (bnc#1155798
    (CPU scheduler functional and performance backports)).

  - sched/fair: Optimize enqueue_task_fair() (bnc#1155798
    (CPU scheduler functional and performance backports)).

  - sched/fair: Simplify the code of should_we_balance()
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - sched: Make newidle_balance() static again (bnc#1155798
    (CPU scheduler functional and performance backports)).

  - sched: Offload wakee task activation if it the wakee is
    descheduling (bnc#1158748, bnc#1159781).

  - sched: Optimize ttwu() spinning on p->on_cpu
    (bnc#1158748, bnc#1159781).

  - sched/pelt: Sync util/runnable_sum with PELT window when
    propagating (bnc#1155798 (CPU scheduler functional and
    performance backports)).

  - scripts/decodecode: fix trapping instruction formatting
    (bsc#1065729).

  - scsi: ibmvscsi: Do not send host info in adapter info
    MAD after LPM (bsc#1172759 ltc#184814).

  - scsi: lpfc: Change default queue allocation for reduced
    memory consumption (bsc#1164777 bsc#1164780 bsc#1165211
    jsc#SLE-8654).

  - scsi: lpfc: Copyright updates for 12.6.0.4 patches
    (bsc#1171530).

  - scsi: lpfc: fix build failure with DEBUGFS disabled
    (bsc#1171530).

  - scsi: lpfc: Fix incomplete NVME discovery when target
    (bsc#1171530).

  - scsi: lpfc: Fix lpfc_nodelist leak when processing
    unsolicited event (bsc#1164777 bsc#1164780 bsc#1165211
    jsc#SLE-8654).

  - scsi: lpfc: Fix MDS Diagnostic Enablement definition
    (bsc#1164777 bsc#1164780 bsc#1165211 jsc#SLE-8654).

  - scsi: lpfc: Fix memory leak on lpfc_bsg_write_ebuf_set
    func (bsc#1171530).

  - scsi: lpfc: Fix negation of else clause in
    lpfc_prep_node_fc4type (bsc#1164777 bsc#1164780
    bsc#1165211 jsc#SLE-8654).

  - scsi: lpfc: Fix noderef and address space warnings
    (bsc#1164777 bsc#1164780 bsc#1165211 jsc#SLE-8654).

  - scsi: lpfc: fix spelling mistakes of asynchronous
    (bsc#1171530).

  - scsi: lpfc: Maintain atomic consistency of queue_claimed
    flag (bsc#1164777 bsc#1164780 bsc#1165211 jsc#SLE-8654).

  - scsi: lpfc: Make lpfc_defer_acc_rsp static
    (bsc#1171530).

  - scsi: lpfc: remove duplicate unloading checks
    (bsc#1164777 bsc#1164780 bsc#1165211 jsc#SLE-8654).

  - scsi: lpfc: Remove re-binding of nvme rport during
    registration (bsc#1164777 bsc#1164780 bsc#1165211
    jsc#SLE-8654).

  - scsi: lpfc: Remove redundant initialization to variable
    rc (bsc#1164777 bsc#1164780 bsc#1165211 jsc#SLE-8654).

  - scsi: lpfc: Remove unnecessary lockdep_assert_held calls
    (bsc#1164777 bsc#1164780 bsc#1165211 jsc#SLE-8654).

  - scsi: lpfc: Update lpfc version to 12.8.0.1 (bsc#1164777
    bsc#1164780 bsc#1165211 jsc#SLE-8654).

  - scsi: megaraid_sas: Replace undefined MFI_BIG_ENDIAN
    macro with __BIG_ENDIAN_BITFIELD macro (bsc#1173206).

  - scsi: qla2xxx: Delete all sessions before unregister
    local nvme port (jsc#SLE-9714 jsc#SLE-10327
    jsc#SLE-10334 bsc#1157169).

  - scsi: qla2xxx: Do not log message when reading port
    speed via sysfs (jsc#SLE-9714 jsc#SLE-10327
    jsc#SLE-10334 bsc#1157169).

  - scsi: qla2xxx: Fix hang when issuing nvme disconnect-all
    in NPIV (jsc#SLE-9714 jsc#SLE-10327 jsc#SLE-10334
    bsc#1157169).

  - scsi: sd_zbc: Fix sd_zbc_complete() (bsc#1173206).

  - scsi: smartpqi: Update attribute name to
    `driver_version` (bsc#1173206).

  - scsi: zfcp: add diagnostics buffer for exchange config
    data (bsc#1158050).

  - scsi: zfcp: auto variables for dereferenced structs in
    open port handler (bsc#1158050).

  - scsi: zfcp: diagnostics buffer caching and use for
    exchange port data (bsc#1158050).

  - scsi: zfcp: enhance handling of FC Endpoint Security
    errors (bsc#1158050).

  - scsi: zfcp: expose fabric name as common fc_host sysfs
    attribute (bsc#1158050).

  - scsi: zfcp: Fence adapter status propagation for common
    statuses (bsc#1158050).

  - scsi: zfcp: Fence early sysfs interfaces for accesses of
    shost objects (bsc#1158050).

  - scsi: zfcp: Fence fc_host updates during link-down
    handling (bsc#1158050).

  - scsi: zfcp: fix fc_host attributes that should be
    unknown on local link down (bsc#1158050).

  - scsi: zfcp: fix wrong data and display format of SFP+
    temperature (bsc#1158050).

  - scsi: zfcp: implicitly refresh config-data diagnostics
    when reading sysfs (bsc#1158050).

  - scsi: zfcp: implicitly refresh port-data diagnostics
    when reading sysfs (bsc#1158050).

  - scsi: zfcp: introduce sysfs interface for diagnostics of
    local SFP transceiver (bsc#1158050).

  - scsi: zfcp: introduce sysfs interface to read the local
    B2B-Credit (bsc#1158050).

  - scsi: zfcp: log FC Endpoint Security errors
    (bsc#1158050).

  - scsi: zfcp: log FC Endpoint Security of connections
    (bsc#1158050).

  - scsi: zfcp: Move allocation of the shost object to after
    xconf- and xport-data (bsc#1158050).

  - scsi: zfcp: Move fc_host updates during xport data
    handling into fenced function (bsc#1158050).

  - scsi: zfcp: move maximum age of diagnostic buffers into
    a per-adapter variable (bsc#1158050).

  - scsi: zfcp: Move p-t-p port allocation to after xport
    data (bsc#1158050).

  - scsi: zfcp: Move shost modification after QDIO (re-)open
    into fenced function (bsc#1158050).

  - scsi: zfcp: Move shost updates during xconfig data
    handling into fenced function (bsc#1158050).

  - scsi: zfcp: proper indentation to reduce confusion in
    zfcp_erp_required_act (bsc#1158050).

  - scsi: zfcp: report FC Endpoint Security in sysfs
    (bsc#1158050).

  - scsi: zfcp: signal incomplete or error for sync exchange
    config/port data (bsc#1158050).

  - scsi: zfcp: support retrieval of SFP Data via Exchange
    Port Data (bsc#1158050).

  - scsi: zfcp: trace FC Endpoint Security of FCP devices
    and connections (bsc#1158050).

  - scsi: zfcp: wire previously driver-specific sysfs
    attributes also to fc_host (bsc#1158050).

  - selftests/bpf: CONFIG_IPV6_SEG6_BPF required for
    test_seg6_loop.o (bsc#1155518).

  - selftests/bpf: CONFIG_LIRC required for
    test_lirc_mode2.sh (bsc#1155518).

  - selftests/bpf: Fix invalid memory reads in core_relo
    selftest (bsc#1155518).

  - selftests/bpf: Fix memory leak in extract_build_id()
    (bsc#1155518).

  - selftests/bpf, flow_dissector: Close TAP device FD after
    the test (bsc#1155518).

  - selftests/timens: handle a case when alarm clocks are
    not supported (bsc#1164648,jsc#SLE-11493).

  - serial: 8250: Fix max baud limit in generic 8250 port
    (git-fixes).

  - slimbus: core: Fix mismatch in of_node_get/put
    (git-fixes).

  - soc: mediatek: cmdq: return send msg error code
    (git-fixes).

  - soc: qcom: rpmh: Dirt can only make you dirtier, not
    cleaner (git-fixes).

  - soc: qcom: rpmh: Invalidate SLEEP and WAKE TCSes before
    flushing new data (git-fixes).

  - soc: qcom: rpmh-rsc: Allow using free WAKE TCS for
    active request (git-fixes).

  - soc: qcom: rpmh-rsc: Clear active mode configuration for
    wake TCS (git-fixes).

  - soc: qcom: rpmh: Update dirty flag only when data
    changes (git-fixes).

  - soc/tegra: pmc: Select GENERIC_PINCONF (git-fixes).

  - spi: bcm2835aux: Fix controller unregister order
    (git-fixes).

  - spi: bcm2835: Fix controller unregister order
    (git-fixes).

  - spi: bcm-qspi: Handle clock probe deferral (git-fixes).

  - spi: bcm-qspi: when tx/rx buffer is NULL set to 0
    (git-fixes).

  - SPI: designware: pci: Switch over to MSI interrupts
    (jsc#SLE-12735).

  - spi: dt-bindings: spi-controller: Fix #address-cells for
    slave mode (git-fixes).

  - spi: dw: Add SPI Rx-done wait method to DMA-based
    transfer (git-fixes).

  - spi: dw: Add SPI Tx-done wait method to DMA-based
    transfer (git-fixes).

  - spi: dw: Fix controller unregister order (git-fixes).

  - spi: dw: Fix native CS being unset (git-fixes).

  - spi: dw-pci: Add MODULE_DEVICE_TABLE (jsc#SLE-12735).

  - spi: dw-pci: Add runtime power management support
    (jsc#SLE-12735).

  - spi: dw-pci: Add support for Intel Elkhart Lake PSE SPI
    (jsc#SLE-12735).

  - spi: dw-pci: Fix Chip Select amount on Intel Elkhart
    Lake PSE SPI (jsc#SLE-12735).

  - spi: dw: use 'smp_mb()' to avoid sending spi data error
    (git-fixes).

  - spi: dw: Zero DMA Tx and Rx configurations on stack
    (git-fixes).

  - spi: Fix controller unregister order (git-fixes).

  - spi: fsl: do not map irq during probe (git-fixes).

  - spi: fsl: use platform_get_irq() instead of
    of_irq_to_resource() (git-fixes).

  - spi: pxa2xx: Fix controller unregister order
    (git-fixes).

  - spi: pxa2xx: Fix runtime PM ref imbalance on probe error
    (git-fixes).

  - spi: Respect DataBitLength field of SpiSerialBusV2()
    ACPI resource (git-fixes).

  - spi: spi-fsl-dspi: Change usage pattern of SPI_MCR_* and
    SPI_CTAR_* macros (git-fixes).

  - spi: spi-fsl-dspi: Do not access reserved fields in
    SPI_MCR (git-fixes).

  - spi: spi-fsl-dspi: Fix 16-bit word order in 32-bit XSPI
    mode (git-fixes).

  - spi: spi-fsl-dspi: Replace interruptible wait queue with
    a simple completion (git-fixes).

  - spi: spi-mem: Fix Dual/Quad modes on Octal-capable
    devices (git-fixes).

  - staging: iio: ad2s1210: Fix SPI reading (git-fixes).

  - staging: kpc2000: fix error return code in
    kp2000_pcie_probe() (git-fixes).

  - staging: rtl8712: Fix
    IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK (git-fixes).

  - staging: sm750fb: add missing case while setting
    FB_VISUAL (git-fixes).

  - sun6i: dsi: fix gcc-4.8 (bsc#1152489)

  - SUNRPC: Signalled ASYNC tasks need to exit (git-fixes).

  - supported.conf: Add pinctrl-tigerlake as supported

  - supported.conf: Mark two hwtracing helper modules as
    externally supported (bsc#1170879)

  - svcrdma: Fix leak of svc_rdma_recv_ctxt objects
    (git-fixes).

  - tcp: cache line align MAX_TCP_HEADER
    (networking-stable-20_04_27).

  - team: fix hang in team_mode_get()
    (networking-stable-20_04_27).

  - thermal: intel: intel_pch_thermal: Add Comet Lake (CML)
    platform support (jsc#SLE-12668).

  - tick/sched: Annotate lockless access to
    last_jiffies_update (bsc#1173438).

  - timer: Use hlist_unhashed_lockless() in timer_pending()
    (bsc#1173438).

  - torture: Allow 'CFLIST' to specify default list of
    scenarios (bsc#1173068).

  - torture: Expand last_ts variable in kvm-test-1-run.sh
    (bsc#1173068).

  - torture: Handle jitter for CPUs that cannot be offlined
    (bsc#1173068).

  - torture: Handle systems lacking the mpstat command
    (bsc#1173068).

  - torture: Hoist calls to lscpu to higher-level kvm.sh
    script (bsc#1173068).

  - torture: Make results-directory date format
    completion-friendly (bsc#1173068).

  - torture: Use gawk instead of awk for systime() function
    (bsc#1173068).

  - tpm: ibmvtpm: retry on H_CLOSED in tpm_ibmvtpm_send()
    (bsc#1065729).

  - tty: n_gsm: Fix bogus i++ in gsm_data_kick (git-fixes).

  - tty: n_gsm: Fix SOF skipping (git-fixes).

  - tty: n_gsm: Fix waking up upper tty layer when room
    available (git-fixes).

  - tty: serial: add missing spin_lock_init for SiFive
    serial console (git-fixes).

  - tun: correct header offsets in napi frags mode
    (git-fixes).

  - Update config files: Add CONFIG_PINCTRL_TIGERLAKE=m

  - Update patch reference for intel_th patch
    (jsc#SLE-12705)

  - Update the patch reference for ish-hid fix
    (jsc#SLE-12683)

  - usb: core: Fix misleading driver bug report (git-fixes).

  - usb: core: hub: limit HUB_QUIRK_DISABLE_AUTOSUSPEND to
    USB5534B (git-fixes).

  - usb: dwc2: gadget: move gadget resume after the core is
    in L0 state (git-fixes).

  - usb: dwc3: gadget: Properly handle ClearFeature(halt)
    (git-fixes).

  - usb: dwc3: gadget: Properly handle failed kick_transfer
    (git-fixes).

  - usb: dwc3: pci: Enable extcon driver for Intel
    Merrifield (git-fixes).

  - usb: gadget: audio: Fix a missing error return value in
    audio_bind() (git-fixes).

  - usb: gadget: fix illegal array access in binding with
    UDC (git-fixes).

  - usb: gadget: fix potential double-free in m66592_probe
    (git-fixes).

  - usb: gadget: legacy: fix error return code in cdc_bind()
    (git-fixes).

  - usb: gadget: legacy: fix error return code in
    gncm_bind() (git-fixes).

  - usb: gadget: legacy: fix redundant initialization
    warnings (git-fixes).

  - usb: gadget: lpc32xx_udc: do not dereference ep pointer
    before null check (git-fixes).

  - usb: gadget: net2272: Fix a memory leak in an error
    handling path in 'net2272_plat_probe()' (git-fixes).

  - usb: gadget: udc: atmel: Make some symbols static
    (git-fixes).

  - usb: gadget: udc: s3c2410_udc: Remove pointless NULL
    check in s3c2410_udc_nuke (git-fixes).

  - usb: host: ehci-mxc: Add error handling in
    ehci_mxc_drv_probe() (git-fixes).

  - usb: host: xhci-plat: keep runtime active when removing
    host (git-fixes).

  - usb: musb: Fix runtime PM imbalance on error
    (git-fixes).

  - usb: musb: start session in resume for host port
    (git-fixes).

  - usb: ohci-sm501: fix error return code in
    ohci_hcd_sm501_drv_probe() (git-fixes).

  - usb: serial: option: add Telit LE910C1-EUX compositions
    (git-fixes).

  - usb: serial: qcserial: add DW5816e QDL support
    (git-fixes).

  - usb: serial: usb_wwan: do not resubmit rx urb on fatal
    errors (git-fixes).

  - usb: usbfs: correct kernel->user page attribute mismatch
    (git-fixes).

  - usb: usbfs: fix mmap dma mismatch (git-fixes).

  - vfio: avoid possible overflow in
    vfio_iommu_type1_pin_pages (git-fixes).

  - vfio: Ignore -ENODEV when getting MSI cookie
    (git-fixes).

  - vfio/mdev: Fix reference count leak in
    add_mdev_supported_type (git-fixes).

  - vfio/pci: fix memory leaks in alloc_perm_bits()
    (git-fixes).

  - vfio/type1: Fix VA->PA translation for PFNMAP VMAs in
    vaddr_get_pfn() (git-fixes).

  - video: fbdev: w100fb: Fix a potential double free
    (git-fixes).

  - virtio-blk: handle block_device_operations callbacks
    after hot unplug (git fixes (block drivers)).

  - vmxnet3: add geneve and vxlan tunnel offload support
    (bsc#1172484).

  - vmxnet3: add support to get/set rx flow hash
    (bsc#1172484).

  - vmxnet3: allow rx flow hash ops only when rss is enabled
    (bsc#1172484).

  - vmxnet3: prepare for version 4 changes (bsc#1172484).

  - vmxnet3: update to version 4 (bsc#1172484).

  - vmxnet3: use correct hdr reference when packet is
    encapsulated (bsc#1172484).

  - vrf: Check skb for XFRM_TRANSFORMED flag
    (networking-stable-20_04_27).

  - vrf: Fix IPv6 with qdisc and xfrm
    (networking-stable-20_04_27).

  - vsprintf: do not obfuscate NULL and error pointers
    (bsc#1172086).

  - vt: vt_ioctl: fix VT_DISALLOCATE freeing in-use virtual
    console (git-fixes).

  - vt: vt_ioctl: remove unnecessary console allocation
    checks (git-fixes).

  - vxlan: use the correct nlattr array in
    NL_SET_ERR_MSG_ATTR (networking-stable-20_04_27).

  - w1: omap-hdq: cleanup to add missing newline for some
    dev_dbg (git-fixes).

  - watchdog: imx_sc_wdt: Fix reboot on crash (git-fixes).

  - wcn36xx: Fix error handling path in 'wcn36xx_probe()'
    (git-fixes).

  - wireguard: device: avoid circular netns references
    (git-fixes).

  - wireguard: noise: do not assign initiation time in if
    condition (git-fixes).

  - wireguard: noise: read preshared key while taking lock
    (bsc#1169021 jsc#SLE-12250).

  - wireguard: noise: separate receive counter from send
    counter (bsc#1169021 jsc#SLE-12250).

  - wireguard: queueing: preserve flow hash across packet
    scrubbing (bsc#1169021 jsc#SLE-12250).

  - wireguard: receive: account for napi_gro_receive never
    returning GRO_DROP (git-fixes).

  - wireguard: selftests: use newer iproute2 for gcc-10
    (bsc#1169021 jsc#SLE-12250).

  - work around mvfs bug (bsc#1162063).

  - workqueue: do not use wq_select_unbound_cpu() for bound
    works (git-fixes).

  - workqueue: Remove the warning in wq_worker_sleeping()
    (git-fixes).

  - x86/cpu/amd: Make erratum #1054 a legacy erratum
    (bsc#1152489).

  - x86: Fix early boot crash on gcc-10, third try
    (bsc#1152489).

  - x86/mm/cpa: Flush direct map alias during cpa
    (bsc#1152489).

  - x86/PCI: Mark Intel C620 MROMs as having non-compliant
    BARs (git-fixes).

  - x86/reboot/quirks: Add MacBook6,1 reboot quirk
    (git-fixes).

  - x86/resctrl: Fix invalid attempt at removing the default
    resource group (bsc#1152489).

  - x86/resctrl: Preserve CDP enable over CPU hotplug
    (bsc#1152489).

  - x86/unwind/orc: Fix unwind_get_return_address_ptr() for
    inactive tasks (bsc#1058115).

  - xfrm: Always set XFRM_TRANSFORMED in
    xfrm(4,6)_output_finish (networking-stable-20_04_27).

  - xfrm: fix error in comment (git fixes (block drivers)).

  - xfs: clean up the error handling in xfs_swap_extents
    (git-fixes).

  - xfs: do not commit sunit/swidth updates to disk if that
    would cause repair failures (bsc#1172169).

  - xfs: do not fail unwritten extent conversion on
    writeback due to edquot (bsc#1158242).

  - xfs: fix duplicate verification from xfs_qm_dqflush()
    (git-fixes).

  - xfs: force writes to delalloc regions to unwritten
    (bsc#1158242).

  - xfs: measure all contiguous previous extents for
    prealloc size (bsc#1158242).

  - xfs: preserve default grace interval during quotacheck
    (bsc#1172170).

  - xfs: refactor agfl length computation function
    (bsc#1172169).

  - xfs: split the sunit parameter update into two parts
    (bsc#1172169).

  - wireguard: selftests: initalize ipv6 members to NULL to
    squelch clang warning (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058115"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148868"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154492"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173461"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.26.2.lp152.8.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.26.2.lp152.8.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.26.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.26.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-debuginfo / kernel-debug-debugsource / etc");
}
