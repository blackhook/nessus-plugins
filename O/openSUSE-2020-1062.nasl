#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1062.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138986);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2020-12771", "CVE-2020-15393");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1062)");
  script_summary(english:"Check for the openSUSE-2020-1062 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The openSUSE Leap 15.2 was updated to receive various security and
bugfixes.

The following security bugs were fixed :

  - CVE-2020-15393: usbtest_disconnect in
    drivers/usb/misc/usbtest.c had a memory leak, aka
    CID-28ebeb8db770 (bnc#1173514).

  - CVE-2020-12771: btree_gc_coalesce in
    drivers/md/bcache/btree.c had a deadlock if a coalescing
    operation fails (bnc#1171732).

The following non-security bugs were fixed :

  - ACPI: configfs: Disallow loading ACPI tables when locked
    down (git-fixes).

  - ACPI: sysfs: Fix pm_profile_attr type (git-fixes).

  - aio: fix async fsync creds (bsc#1173828).

  - ALSA: hda: Add NVIDIA codec IDs 9a & 9d through a0 to
    patch table (git-fixes).

  - ALSA: hda/hdmi: fix failures at PCM open on Intel ICL
    and later (git-fixes).

  - ALSA: hda/hdmi: improve debug traces for stream lookups
    (git-fixes).

  - ALSA: hda - let hs_mic be picked ahead of hp_mic
    (git-fixes).

  - ALSA: hda/realtek: Add mute LED and micmute LED support
    for HP systems (git-fixes).

  - ALSA: hda/realtek - Add quirk for MSI GE63 laptop
    (git-fixes).

  - ALSA: hda/realtek - Enable audio jacks of Acer
    vCopperbox with ALC269VC (git-fixes).

  - ALSA: hda/realtek: Enable headset mic of Acer C20-820
    with ALC269VC (git-fixes).

  - ALSA: hda/realtek: Enable headset mic of Acer Veriton
    N4660G with ALC269VC (git-fixes).

  - ALSA: hda/realtek - Fix Lenovo Thinkpad X1 Carbon 7th
    quirk subdevice id (git-fixes).

  - ALSA: isa/wavefront: prevent out of bounds write in
    ioctl (git-fixes).

  - ALSA: opl3: fix infoleak in opl3 (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for RTX6001
    (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for SSL2+
    (git-fixes).

  - ALSA: usb-audio: add quirk for Denon DCD-1500RE
    (git-fixes).

  - ALSA: usb-audio: add quirk for MacroSilicon MS2109
    (git-fixes).

  - ALSA: usb-audio: add quirk for Samsung USBC Headset
    (AKG) (git-fixes).

  - ALSA: usb-audio: Fix OOB access of mixer element list
    (git-fixes).

  - ALSA: usb-audio: Fix packet size calculation
    (bsc#1173847).

  - ALSA: usb-audio: Fix potential use-after-free of streams
    (git-fixes).

  - ALSA: usb-audio: Replace s/frame/packet/ where
    appropriate (git-fixes).

  - amdgpu: a NULL ->mm does not mean a thread is a kthread
    (git-fixes).

  - ASoC: core: only convert non DPCM link to DPCM link
    (git-fixes).

  - ASoC: davinci-mcasp: Fix dma_chan refcnt leak when
    getting dma type (git-fixes).

  - ASoC: fsl_asrc_dma: Fix dma_chan leak when config DMA
    channel failed (git-fixes).

  - ASoC: fsl_ssi: Fix bclk calculation for mono channel
    (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for Toshiba Encore
    WT8-A tablet (git-fixes).

  - ASoC: max98373: reorder max98373_reset() in resume
    (git-fixes).

  - ASoc: q6afe: add support to get port direction
    (git-fixes).

  - ASoC: q6asm: handle EOS correctly (git-fixes).

  - ASoC: qcom: q6asm-dai: kCFI fix (git-fixes).

  - ASoC: rockchip: Fix a reference count leak (git-fixes).

  - ASoC: SOF: Do nothing when DSP PM callbacks are not set
    (git-fixes).

  - ASoC: SOF: nocodec: conditionally set
    dpcm_capture/dpcm_playback flags (git-fixes).

  - ASoC: tegra: tegra_wm8903: Support nvidia, headset
    property (git-fixes).

  - ASoC: ti: omap-mcbsp: Fix an error handling path in
    'asoc_mcbsp_probe()' (git-fixes).

  - ata/libata: Fix usage of page address by page_address in
    ata_scsi_mode_select_xlat function (git-fixes).

  - ath10k: fix kernel NULL pointer dereference (git-fixes).

  - ath10k: Fix the race condition in firmware dump work
    queue (git-fixes).

  - b43: Fix connection problem with WPA3 (git-fixes).

  - b43_legacy: Fix connection problem with WPA3
    (git-fixes).

  - backlight: lp855x: Ensure regulators are disabled on
    probe failure (git-fixes).

  - batman-adv: Revert 'disable ethtool link speed detection
    when auto negotiation off' (git-fixes).

  - bdev: fix bdev inode reference count disbalance
    regression (bsc#1174244)

  - block/bio-integrity: do not free 'buf' if
    bio_integrity_add_page() failed (bsc#1173817).

  - block: Fix use-after-free in blkdev_get() (bsc#1173834).

  - block: nr_sects_write(): Disable preemption on seqcount
    write (bsc#1173818).

  - Bluetooth: Add SCO fallback for invalid LMP parameters
    error (git-fixes).

  - Bluetooth: btbcm: Add 2 missing models to subver tables
    (git-fixes).

  - bnxt_en: Fix AER reset logic on 57500 chips
    (bsc#1171150).

  - bnxt_en: fix firmware message length endianness
    (bsc#1173894).

  - bnxt_en: Fix return code to 'flash_device'
    (bsc#1173894).

  - bnxt_en: Re-enable SRIOV during resume (jsc#SLE-8371
    bsc#1153274).

  - bnxt_en: Return from timer if interface is not in open
    state (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Simplify bnxt_resume() (jsc#SLE-8371
    bsc#1153274).

  - bpf: Document optval > PAGE_SIZE behavior for sockopt
    hooks (bsc#1155518).

  - bpf: Do not return EINVAL from (get,set)sockopt when
    optlen > PAGE_SIZE (bsc#1155518).

  - bpf: Fix an error code in check_btf_func()
    (bsc#1154353).

  - bpf: Restrict bpf_trace_printk()'s %s usage and add
    %pks, %pus specifier (bsc#1172344).

  - bpf, xdp, samples: Fix NULL pointer dereference in
    *_user code (bsc#1155518).

  - brcmfmac: expose RPi firmware config files through
    modinfo (bsc#1169094).

  - bus: ti-sysc: Ignore clockactivity unless specified as a
    quirk (git-fixes).

  - carl9170: remove P2P_GO support (git-fixes).

  - cdc-acm: Add DISABLE_ECHO quirk for Microchip/SMSC chip
    (git-fixes).

  - clk: qcom: msm8916: Fix the address location of
    pll->config_reg (git-fixes).

  - clk: samsung: exynos5433: Add IGNORE_UNUSED flag to
    sclk_i2s1 (git-fixes).

  - clk: sifive: allocate sufficient memory for struct
    __prci_data (git-fixes).

  - clk: ti: composite: fix memory leak (git-fixes).

  - clk: zynqmp: fix memory leak in zynqmp_register_clocks
    (git-fixes).

  - clocksource: dw_apb_timer: Make CPU-affiliation being
    optional (git-fixes).

  - cpufreq: Fix up cpufreq_boost_set_sw() (git-fixes).

  - cpufreq: intel_pstate: Only mention the BIOS disabling
    turbo mode once (git-fixes).

  - cpufreq: powernv: Fix frame-size-overflow in
    powernv_cpufreq_work_fn (git-fixes).

  - cpuidle: Fix three reference count leaks (git-fixes).

  - crypto: algif_skcipher - Cap recv SG list at ctx->used
    (git-fixes).

  - crypto - Avoid free() namespace collision (git-fixes).

  - Crypto/chcr: fix for ccm(aes) failed test (git-fixes).

  - crypto: omap-sham - add proper load balancing support
    for multicore (git-fixes).

  - debugfs: Check module state before warning in
    (full/open)_proxy_open() (bsc#1173746).

  - devlink: fix return value after hitting end in region
    read (networking-stable-20_05_12).

  - devmap: Use bpf_map_area_alloc() for allocating hash
    buckets (bsc#1154353).

  - dm writecache: reject asynchronous pmem devices
    (bsc#1156395).

  - dpaa2-eth: prevent array underflow in update_cls_rule()
    (networking-stable-20_05_16).

  - dpaa2-eth: properly handle buffer size restrictions
    (networking-stable-20_05_16).

  - dpaa_eth: fix usage as DSA master, try 3
    (networking-stable-20_05_27).

  - drivers: base: Fix NULL pointer exception in
    __platform_driver_probe() if a driver developer is
    foolish (git-fixes).

  - Drivers: hv: Change flag to write log level in panic msg
    to false (bsc#1170617).

  - drm: amd/display: fix Kconfig help text (bsc#1152489)
    &#9;* context changes

  - drm/amd/display: Revalidate bandwidth before commiting
    DC updates (git-fixes).

  - drm/amd: fix potential memleak in err branch
    (git-fixes).

  - drm/amdgpu: add fw release for sdma v5_0 (git-fixes).

  - drm/amdgpu: drop redundant cg/pg ungate on runpm enter
    (git-fixes).

  - drm/amdgpu: fix gfx hang during suspend with video
    playback (v2) (git-fixes).

  - drm/amdgpu: fix the hw hang during perform system reboot
    and reset (git-fixes).

  - drm/amdgpu: Init data to avoid oops while reading
    pp_num_states (git-fixes).

  - drm/amdgpu: move kfd suspend after ip_suspend_phase1
    (git-fixes).

  - drm/amdgpu: Replace invalid device ID with a valid
    device ID (bsc#1152472)

  - drm/amd/powerpay: Disable gfxoff when setting manual
    mode on picasso and raven (git-fixes).

  - drm: bridge: adv7511: Extend list of audio sample rates
    (git-fixes).

  - drm/connector: notify userspace on hotplug after
    register complete (bsc#1152489) &#9;* context changes

  - drm/i915/gt: Do not schedule normal requests immediately
    along (bsc#1152489)

  - drm/i915/gvt: Fix two CFL MMIO handling caused by
    regression. (bsc#1152489)

  - drm/i915/gvt: Fix two CFL MMIO handling caused by
    regression (git-fixes).

  - drm/i915/icl+: Fix hotplug interrupt disabling after
    storm detection (bsc#1152489)

  - drm/msm: Check for powered down HW in the devfreq
    callbacks (bsc#1152489)

  - drm/msm/dpu: fix error return code in dpu_encoder_init
    (bsc#1152489)

  - drm/msm/dpu: fix error return code in dpu_encoder_init
    (git-fixes).

  - drm/msm/mdp5: Fix mdp5_init error path for failed
    mdp5_kms allocation (git-fixes).

  - drm/nouveau/disp/gm200-: fix NV_PDISP_SOR_HDMI2_CTRL(n)
    selection (git-fixes).

  - drm/qxl: Use correct notify port address when creating
    cursor ring (bsc#1152472)

  - drm/radeon: fix fb_div check in ni_init_smc_spll_table()
    (bsc#1152472)

  - drm: rcar-du: Fix build error (bsc#1152472)

  - drm: sun4i: hdmi: Remove extra HPD polling (bsc#1152489)

  - drm: sun4i: hdmi: Remove extra HPD polling (git-fixes).

  - e1000: Distribute switch variables for initialization
    (git-fixes).

  - e1000e: Relax condition to trigger reset for ME
    workaround (git-fixes).

  - ext4: avoid utf8_strncasecmp() with unstable name
    (bsc#1173843).

  - ext4: fix error pointer dereference (bsc#1173837).

  - ext4: fix EXT_MAX_EXTENT/INDEX to check for zeroed
    eh_max (bsc#1173836).

  - ext4: fix partial cluster initialization when splitting
    extent (bsc#1173839).

  - ext4: fix race between ext4_sync_parent() and rename()
    (bsc#1173838).

  - ext4, jbd2: ensure panic by fix a race between jbd2
    abort and ext4 error handlers (bsc#1173833).

  - ext4: stop overwrite the errcode in ext4_setup_super
    (bsc#1173841).

  - fat: do not allow to mount if the FAT length == 0
    (bsc#1173831).

  - Fix boot crash with MD (bsc#1173860)

  - fix multiplication overflow in copy_fdtable()
    (bsc#1173825).

  - fork: prevent accidental access to clone3 features
    (bsc#1174018).

  - fq_codel: fix TCA_FQ_CODEL_DROP_BATCH_SIZE sanity checks
    (networking-stable-20_05_12).

  - geneve: allow changing DF behavior after creation
    (git-fixes).

  - geneve: change from tx_error to tx_dropped on missing
    metadata (git-fixes).

  - gfs2: fix glock reference problem in
    gfs2_trans_remove_revoke (bsc#1173823).

  - gfs2: Multi-block allocations in gfs2_page_mkwrite
    (bsc#1173822).

  - gpio: pca953x: fix handling of automatic address
    incrementing (git-fixes).

  - HID: Add quirks for Trust Panora Graphic Tablet
    (git-fixes).

  - hinic: fix a bug of ndo_stop
    (networking-stable-20_05_16).

  - hinic: fix wrong para of wait_for_completion_timeout
    (networking-stable-20_05_16).

  - hv_netvsc: Fix netvsc_start_xmit's return type
    (git-fixes).

  - hwmon: (acpi_power_meter) Fix potential memory leak in
    acpi_power_meter_add() (git-fixes).

  - hwmon: (k10temp) Add AMD family 17h model 60h PCI match
    (git-fixes).

  - hwmon: (max6697) Make sure the OVERT mask is set
    correctly (git-fixes).

  - hwmon: (pmbus) fix a typo in Kconfig SENSORS_IR35221
    option (git-fixes).

  - i2c: algo-pca: Add 0x78 as SCL stuck low status for
    PCA9665 (git-fixes).

  - i2c: core: check returned size of emulated smbus block
    read (git-fixes).

  - i2c: fsi: Fix the port number field in status register
    (git-fixes).

  - i2c: mlxcpld: check correct size of maximum RECV_LEN
    packet (git-fixes).

  - i2c: piix4: Detect secondary SMBus controller on AMD AM4
    chipsets (git-fixes).

  - i2c: pxa: clear all master action bits in
    i2c_pxa_stop_message() (git-fixes).

  - i2c: pxa: fix i2c_pxa_scream_blue_murder() debug output
    (git-fixes).

  - IB/rdmavt: Free kernel completion queue when done
    (bsc#1173625).

  - iio: bmp280: fix compensation of humidity (git-fixes).

  - input: i8042 - Remove special PowerPC handling
    (git-fixes).

  - ionic: add pcie_print_link_status (bsc#1167773).

  - ionic: export features for vlans to use (bsc#1167773).

  - ionic: no link check while resetting queues
    (bsc#1167773).

  - ionic: remove support for mgmt device (bsc#1167773).

  - ionic: tame the watchdog timer on reconfig
    (bsc#1167773).

  - ionic: wait on queue start until after IFF_UP
    (bsc#1167773).

  - io_uring: use kvfree() in io_sqe_buffer_register()
    (bsc#1173832).

  - ipmi: use vzalloc instead of kmalloc for user creation
    (git-fixes).

  - iwlwifi: mvm: fix aux station leak (git-fixes).

  - ixgbe: do not check firmware errors (bsc#1170284).

  - jbd2: avoid leaking transaction credits when unreserving
    handle (bsc#1173845).

  - jbd2: Preserve kABI when adding j_abort_mutex
    (bsc#1173833).

  - kABI fixup mtk-vpu: avoid unaligned access to DTCM
    buffer (git-fixes).

  - kabi: hv: prevent struct device_node to become defined
    (bsc#1172871).

  - kABI: protect struct fib_dump_filter (kabi).

  - kABI: protect struct mlx5_cmd_work_ent (kabi).

  - libceph: do not omit recovery_deletes in target_copy()
    (git-fixes).

  - loop: replace kill_bdev with invalidate_bdev
    (bsc#1173820).

  - media: dvbdev: Fix tuner->demod media controller link
    (git-fixes).

  - media: dvbsky: add support for eyeTV Geniatech T2 lite
    (bsc#1173776).

  - media: dvbsky: add support for Mygica T230C v2
    (bsc#1173776).

  - media: imx: imx7-mipi-csis: Cleanup and fix subdev pad
    format handling (git-fixes).

  - media: mtk-vpu: avoid unaligned access to DTCM buffer
    (git-fixes).

  - media: ov5640: fix use of destroyed mutex (git-fixes).

  - media: si2157: Better check for running tuner in init
    (git-fixes).

  - media: si2168: add support for Mygica T230C v2
    (bsc#1173776).

  - media: staging: imgu: do not hold spinlock during
    freeing mmu page table (git-fixes).

  - media: staging/intel-ipu3: Implement lock for stream
    on/off operations (git-fixes).

  - media: vicodec: Fix error codes in probe function
    (git-fixes).

  - mfd: wm8994: Fix driver operation if loaded as modules
    (git-fixes).

  - mlxsw: spectrum_acl_tcam: Position vchunk in a vregion
    list properly (networking-stable-20_05_12).

  - mmc: sdhci-msm: Set SDHCI_QUIRK_MULTIBLOCK_READ_ACMD12
    quirk (git-fixes).

  - mmc: via-sdmmc: Respect the cmd->busy_timeout from the
    mmc core (git-fixes).

  - mm: fix NUMA node file count error in
    replace_page_cache() (bsc#1173844).

  - mm/memory_hotplug: refrain from adding memory into an
    impossible node (bsc#1173552).

  - mvpp2: remove module bugfix (bsc#1154353).

  - namei: only return -ECHILD from follow_dotdot_rcu()
    (bsc#1173824).

  - neigh: send protocol value in neighbor create
    notification (networking-stable-20_05_12).

  - net: core: device_rename: Use rwsem instead of a
    seqcount (bsc#1162702).

  - net: do not return invalid table id error when we fall
    back to PF_UNSPEC (networking-stable-20_05_27).

  - net: dsa: Do not leave DSA master with NULL netdev_ops
    (networking-stable-20_05_12).

  - net: dsa: loop: Add module soft dependency
    (networking-stable-20_05_16).

  - net: dsa: mt7530: fix roaming from DSA user ports
    (networking-stable-20_05_27).

  - net: ethernet: ti: cpsw: fix ASSERT_RTNL() warning
    during suspend (networking-stable-20_05_27).

  - net: fix a potential recursive NETDEV_FEAT_CHANGE
    (networking-stable-20_05_16).

  - __netif_receive_skb_core: pass skb by reference
    (networking-stable-20_05_27).

  - net: inet_csk: Fix so_reuseport bind-address cache in
    tb->fast* (networking-stable-20_05_27).

  - net: ipip: fix wrong address family in init error path
    (networking-stable-20_05_27).

  - net: macb: fix an issue about leak related system
    resources (networking-stable-20_05_12).

  - net: macsec: preserve ingress frame ordering
    (networking-stable-20_05_12).

  - net/mlx4_core: Fix use of ENOSPC around
    mlx4_counter_alloc() (networking-stable-20_05_12).

  - net/mlx5: Add command entry handling completion
    (networking-stable-20_05_27).

  - net/mlx5: Disable reload while removing the device
    (jsc#SLE-8464).

  - net/mlx5: DR, Fix freeing in dr_create_rc_qp()
    (jsc#SLE-8464).

  - net/mlx5e: Fix inner tirs handling
    (networking-stable-20_05_27).

  - net/mlx5e: kTLS, Destroy key object after destroying the
    TIS (networking-stable-20_05_27).

  - net/mlx5e: Update netdev txq on completions during
    closure (networking-stable-20_05_27).

  - net/mlx5: Fix command entry leak in Internal Error State
    (networking-stable-20_05_12).

  - net/mlx5: Fix error flow in case of function_setup
    failure (networking-stable-20_05_27).

  - net/mlx5: Fix forced completion access non initialized
    command entry (networking-stable-20_05_12).

  - net/mlx5: Fix memory leak in mlx5_events_init
    (networking-stable-20_05_27).

  - net: mvpp2: cls: Prevent buffer overflow in
    mvpp2_ethtool_cls_rule_del()
    (networking-stable-20_05_12).

  - net: mvpp2: fix RX hashing for non-10G ports
    (networking-stable-20_05_27).

  - net: mvpp2: prevent buffer overflow in mvpp22_rss_ctx()
    (networking-stable-20_05_12).

  - net: nlmsg_cancel() if put fails for nhmsg
    (networking-stable-20_05_27).

  - net: phy: fix aneg restart in phy_ethtool_set_eee
    (networking-stable-20_05_16).

  - netprio_cgroup: Fix unlimited memory leak of v2 cgroups
    (networking-stable-20_05_16).

  - net: qrtr: Fix passing invalid reference to
    qrtr_local_enqueue() (networking-stable-20_05_27).

  - net sched: fix reporting the first-time use timestamp
    (networking-stable-20_05_27).

  - net_sched: sch_skbprio: add message validation to
    skbprio_change() (networking-stable-20_05_12).

  - net/smc: tolerate future SMCD versions (bsc#1172543
    LTC#186069).

  - net: stmmac: fix num_por initialization
    (networking-stable-20_05_16).

  - net: stricter validation of untrusted gso packets
    (networking-stable-20_05_12).

  - net: tc35815: Fix phydev supported/advertising mask
    (networking-stable-20_05_12).

  - net: tcp: fix rx timestamp behavior for tcp_recvmsg
    (networking-stable-20_05_16).

  - net/tls: fix race condition causing kernel panic
    (networking-stable-20_05_27).

  - net/tls: Fix sk_psock refcnt leak in
    bpf_exec_tx_verdict() (networking-stable-20_05_12).

  - net/tls: Fix sk_psock refcnt leak when in
    tls_data_ready() (networking-stable-20_05_12).

  - net: usb: qmi_wwan: add support for DW5816e
    (networking-stable-20_05_12).

  - nexthop: Fix attribute checking for groups
    (networking-stable-20_05_27).

  - nfp: abm: fix a memory leak bug
    (networking-stable-20_05_12).

  - nfp: abm: fix error return code in nfp_abm_vnic_alloc()
    (networking-stable-20_05_16).

  - nfsd4: fix nfsdfs reference count loop (git-fixes).

  - nfsd: apply umask on fs without ACL support (git-fixes).

  - nfsd: fix nfsdfs inode reference count leak (git-fixes).

  - NFSv4 fix CLOSE not waiting for direct IO compeletion
    (git-fixes).

  - PCI: aardvark: Do not blindly enable ASPM L0s and do not
    write to read-only register (git-fixes).

  - PCI: Add ACS quirk for Intel Root Complex Integrated
    Endpoints (git-fixes).

  - PCI: Add Loongson vendor ID (git-fixes).

  - PCI/ASPM: Allow ASPM on links to PCIe-to-PCI/PCI-X
    Bridges (git-fixes).

  - PCI: Avoid FLR for AMD Matisse HD Audio & USB 3.0
    (git-fixes).

  - PCI: Avoid FLR for AMD Starship USB 3.0 (git-fixes).

  - PCI: Do not disable decoding when mmio_always_on is set
    (git-fixes).

  - PCI: dwc: Fix inner MSI IRQ domain registration
    (git-fixes).

  - PCI: hv: Change pci_protocol_version to per-hbus
    (bsc#1172871).

  - PCI: hv: Decouple the func definition in hv_dr_state
    from VSP message (bsc#1172871).

  - PCI: hv: Fix the PCI HyperV probe failure path to
    release resource properly (bsc#1172871).

  - PCI: hv: Introduce hv_msi_entry (bsc#1172871).

  - PCI: hv: Move hypercall related definitions into tlfs
    header (bsc#1172871).

  - PCI: hv: Move retarget related structures into tlfs
    header (bsc#1172871).

  - PCI: hv: Reorganize the code in preparation of
    hibernation (bsc#1172871).

  - PCI: hv: Retry PCI bus D0 entry on invalid device state
    (bsc#1172871).

  - PCI: pci-bridge-emul: Fix PCIe bit conflicts
    (git-fixes).

  - PCI: vmd: Add device id for VMD device 8086:9A0B
    (git-fixes).

  - pinctrl: rockchip: fix memleak in
    rockchip_dt_node_to_map (git-fixes).

  - pinctrl: tegra: Use noirq suspend/resume callbacks
    (git-fixes).

  - platform/x86: asus_wmi: Reserve more space for struct
    bias_args (git-fixes).

  - platform/x86: hp-wmi: Convert simple_strtoul() to
    kstrtou32() (git-fixes).

  - platform/x86: intel-hid: Add a quirk to support HP
    Spectre X2 (2015) (git-fixes).

  - pNFS/flexfiles: Fix list corruption if the mirror count
    changes (git-fixes).

  - pppoe: only process PADT targeted at local interfaces
    (networking-stable-20_05_16).

  - proc: Use new_inode not new_inode_pseudo (bsc#1173830).

  - pwm: img: Call pm_runtime_put() in pm_runtime_get_sync()
    failed case (git-fixes).

  - RDMA/core: Check that type_attrs is not NULL prior
    access (jsc#SLE-8449).

  - regualtor: pfuze100: correct sw1a/sw2 on pfuze3000
    (git-fixes).

  - remoteproc: qcom_q6v5_mss: map/unmap mpss segments
    before/after use (git-fixes).

  - Revert commit e918e570415c ('tpm_tis: Remove the HID
    IFX0102') (git-fixes).

  - Revert 'i2c: tegra: Fix suspending in active runtime PM
    state' (git-fixes).

  - Revert 'ipv6: add mtu lock check in
    __ip6_rt_update_pmtu' (networking-stable-20_05_16).

  - ring-buffer: Zero out time extend if it is nested and
    not absolute (git-fixes).

  - sata_rcar: handle pm_runtime_get_sync failure cases
    (git-fixes).

  - sch_choke: avoid potential panic in choke_reset()
    (networking-stable-20_05_12).

  - sched: Fix loadavg accounting race (bnc#1155798 (CPU
    scheduler functional and performance backports)).

  - sched: Fix race against ptrace_freeze_trace()
    (bsc#1174345).

  - sch_sfq: validate silly quantum values
    (networking-stable-20_05_12).

  - scsi: lpfc: Add an internal trace log buffer
    (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Add blk_io_poll support for latency
    improvment (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Add support to display if adapter dumps are
    available (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Allow applications to issue Common Set
    Features mailbox command (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix inconsistent indenting (bsc#1172687
    bsc#1171530).

  - scsi: lpfc: Fix interrupt assignments when multiple
    vectors are supported on same CPU (bsc#1172687
    bsc#1171530).

  - scsi: lpfc: Fix kdump hang on PPC (bsc#1172687
    bsc#1171530).

  - scsi: lpfc: Fix language in 0373 message to reflect
    non-error message (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix less-than-zero comparison of unsigned
    value (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix missing MDS functionality (bsc#1172687
    bsc#1171530).

  - scsi: lpfc: Fix NVMe rport deregister and registration
    during ADISC (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix oops due to overrun when reading SLI3
    data (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix shost refcount mismatch when deleting
    vport (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix stack trace seen while setting rrq
    active (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Fix unused assignment in
    lpfc_sli4_bsg_link_diag_test (bsc#1172687 bsc#1171530).

  - scsi: lpfc: Update lpfc version to 12.8.0.2 (bsc#1172687
    bsc#1171530).

  - scsi: qla2xxx: Set NVMe status code for failed NVMe FCP
    request (bsc#1158983).

  - sctp: Do not add the shutdown timer if its already been
    added (networking-stable-20_05_27).

  - sctp: Start shutdown on association restart if in
    SHUTDOWN-SENT state and socket is closed
    (networking-stable-20_05_27).

  - selftests/bpf: Make sure optvals > PAGE_SIZE are
    bypassed (bsc#1155518).

  - signal: Avoid corrupting si_pid and si_uid in
    do_notify_parent (bsc#1171529).

  - slimbus: ngd: get drvdata from correct device
    (git-fixes).

  - socionext: account for napi_gro_receive never returning
    GRO_DROP (bsc#1154353).

  - spi: dw: Enable interrupts in accordance with DMA xfer
    mode (git-fixes).

  - spi: dw: Fix Rx-only DMA transfers (git-fixes).

  - spi: dw: Return any value retrieved from the
    dma_transfer callback (git-fixes).

  - spi: pxa2xx: Apply CS clk quirk to BXT (git-fixes).

  - spi: sprd: switch the sequence of setting WDG_LOAD_LOW
    and _HIGH (git-fixes).

  - Staging: rtl8723bs: prevent buffer overflow in
    update_sta_support_rate() (git-fixes).

  - sunrpc: fixed rollback in rpc_gssd_dummy_populate()
    (git-fixes).

  - SUNRPC: Properly set the @subbuf parameter of
    xdr_buf_subsegment() (git-fixes).

  - tcp: fix error recovery in tcp_zerocopy_receive()
    (networking-stable-20_05_16).

  - tcp: fix SO_RCVLOWAT hangs with fat skbs
    (networking-stable-20_05_16).

  - tg3: driver sleeps indefinitely when EEH errors exceed
    eeh_max_freezes (bsc#1173284).

  - thermal/drivers/mediatek: Fix bank number settings on
    mt8183 (git-fixes).

  - thermal/drivers/rcar_gen3: Fix undefined temperature if
    negative (git-fixes).

  - thermal/drivers/ti-soc-thermal: Avoid dereferencing
    ERR_PTR (git-fixes).

  - tipc: block BH before using dst_cache
    (networking-stable-20_05_27).

  - tipc: fix partial topology connection closure
    (networking-stable-20_05_12).

  - tpm: Fix TIS locality timeout problems (git-fixes).

  - tpm_tis: Remove the HID IFX0102 (git-fixes).

  - tracing: Fix event trigger to accept redundant spaces
    (git-fixes).

  - tunnel: Propagate ECT(1) when decapsulating as
    recommended by RFC6040 (networking-stable-20_05_12).

  - ubifs: fix wrong use of crypto_shash_descsize()
    (bsc#1173827).

  - ubifs: remove broken lazytime support (bsc#1173826).

  - Update patch reference tag for ACPI lockdown fix
    (bsc#1173573)

  - usb: add USB_QUIRK_DELAY_INIT for Logitech C922
    (git-fixes).

  - usb/ehci-platform: Set PM runtime as active on resume
    (git-fixes).

  - USB: ehci: reopen solution for Synopsys HC bug
    (git-fixes).

  - usb: gadget: udc: Potential Oops in error handling code
    (git-fixes).

  - usb: host: ehci-exynos: Fix error check in
    exynos_ehci_probe() (git-fixes).

  - usb: host: ehci-platform: add a quirk to avoid stuck
    (git-fixes).

  - usb: host: xhci-mtk: avoid runtime suspend when removing
    hcd (git-fixes).

  - usblp: poison URBs upon disconnect (git-fixes).

  - usb/ohci-platform: Fix a warning when hibernating
    (git-fixes).

  - USB: ohci-sm501: Add missed iounmap() in remove
    (git-fixes).

  - usb: renesas_usbhs: getting residue from callback_result
    (git-fixes).

  - USB: serial: ch341: add basis for quirk detection
    (git-fixes).

  - usb: typec: tcpci_rt1711h: avoid screaming irq causing
    boot hangs (git-fixes).

  - usb/xhci-plat: Set PM runtime as active on resume
    (git-fixes).

  - video: vt8500lcdfb: fix fallthrough warning
    (bsc#1152489)

  - virtio_net: fix lockdep warning on 32 bit
    (networking-stable-20_05_16).

  - watchdog: da9062: No need to ping manually before
    setting timeout (git-fixes).

  - wil6210: account for napi_gro_receive never returning
    GRO_DROP (bsc#1154353).

  - wil6210: add wil_netif_rx() helper function
    (bsc#1154353).

  - wil6210: use after free in wil_netif_rx_any()
    (bsc#1154353).

  - x86/amd_nb: Add AMD family 17h model 60h PCI IDs
    (git-fixes).

  - xhci: Fix enumeration issue when setting max packet size
    for FS devices (git-fixes).

  - xhci: Fix incorrect EP_STATE_MASK (git-fixes).

  - xhci: Poll for U0 after disabling USB2 LPM (git-fixes).

  - xhci: Return if xHCI does not support LPM (git-fixes).

  - xprtrdma: Fix handling of RDMA_ERROR replies
    (git-fixes)."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174345"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");
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

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.33.1.lp152.8.4.4") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.33.1.lp152.8.4.4") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.33.1") ) flag++;

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
