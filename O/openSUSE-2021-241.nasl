#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-241.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146293);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2020-25211",
    "CVE-2020-29568",
    "CVE-2020-29569",
    "CVE-2021-0342",
    "CVE-2021-3347",
    "CVE-2021-3348",
    "CVE-2021-20177"
  );

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2021-241)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2021-3347: A use-after-free was discovered in the PI
    futexes during fault handling, allowing local users to
    execute code in the kernel (bnc#1181349).

  - CVE-2021-3348: Fixed a use-after-free in nbd_add_socket
    that could be triggered by local attackers (with access
    to the nbd device) via an I/O request at a certain point
    during device setup (bnc#1181504).

  - CVE-2021-20177: Fixed a kernel panic related to iptables
    string matching rules. A privileged user could insert a
    rule which could lead to denial of service
    (bnc#1180765).

  - CVE-2021-0342: In tun_get_user of tun.c, there is
    possible memory corruption due to a use after free. This
    could lead to local escalation of privilege with System
    execution privileges required. (bnc#1180812)

  - CVE-2020-29569: Fixed a potential privilege escalation
    and information leaks related to the PV block backend,
    as used by Xen (bnc#1179509).

  - CVE-2020-29568: Fixed a denial of service issue, related
    to processing watch events (bnc#1179508).

  - CVE-2020-25211: Fixed a flaw where a local attacker was
    able to inject conntrack netlink configuration that
    could cause a denial of service or trigger the use of
    incorrect protocol numbers in
    ctnetlink_parse_tuple_filter (bnc#1176395).

The following non-security bugs were fixed :

  - ACPI/IORT: Do not blindly trust DMA masks from firmware
    (git-fixes).

  - ACPI: scan: add stub acpi_create_platform_device() for
    !CONFIG_ACPI (git-fixes).

  - ACPI: scan: Harden acpi_device_add() against device ID
    overflows (git-fixes).

  - ACPI: scan: Make acpi_bus_get_device() clear return
    pointer on error (git-fixes).

  - ACPI: sysfs: Prefer 'compatible' modalias (git-fixes).

  - ALSA: doc: Fix reference to mixart.rst (git-fixes).

  - ALSA: fireface: Fix integer overflow in
    transmit_midi_msg() (git-fixes).

  - ALSA: firewire-tascam: Fix integer overflow in
    midi_port_work() (git-fixes).

  - ALSA: hda: Add Cometlake-R PCI ID (git-fixes).

  - ALSA: hda/hdmi - enable runtime pm for CI AMD display
    audio (git-fixes).

  - ALSA: hda/realtek: Enable headset of ASUS B1400CEPE with
    ALC256 (git-fixes).

  - ALSA: hda/realtek: fix right sounds and mute/micmute
    LEDs for HP machines (git-fixes).

  - ALSA: hda/realtek - Limit int mic boost on Acer Aspire
    E5-575T (git-fixes).

  - ALSA: hda/tegra: fix tegra-hda on tegra30 soc
    (git-fixes).

  - ALSA: hda/via: Add minimum mute flag (git-fixes).

  - ALSA: hda/via: Apply the workaround generically for
    Clevo machines (git-fixes).

  - ALSA: pcm: fix hw_rule deps kABI (bsc#1181014).

  - ALSA: pcm: One more dependency for hw constraints
    (bsc#1181014).

  - ALSA: seq: oss: Fix missing error check in
    snd_seq_oss_synth_make_info() (git-fixes).

  - ALSA: usb-audio: Always apply the hw constraints for
    implicit fb sync (bsc#1181014).

  - ALSA: usb-audio: Annotate the endpoint index in
    audioformat (git-fixes).

  - ALSA: usb-audio: Avoid implicit feedback on Pioneer
    devices (bsc#1181014).

  - ALSA: usb-audio: Avoid unnecessary interface re-setup
    (git-fixes).

  - ALSA: usb-audio: Choose audioformat of a counter-part
    substream (git-fixes).

  - ALSA: usb-audio: Fix hw constraints dependencies
    (bsc#1181014).

  - ALSA: usb-audio: Fix implicit feedback sync setup for
    Pioneer devices (git-fixes).

  - ALSA: usb-audio: Fix the missing endpoints creations for
    quirks (git-fixes).

  - ALSA: usb-audio: Fix UAC1 rate setup for secondary
    endpoints (bsc#1181014).

  - ALSA: usb-audio: Set sample rate for all sharing EPs on
    UAC1 (bsc#1181014).

  - arch/x86/lib/usercopy_64.c: fix __copy_user_flushcache()
    cache writeback (bsc#1152489).

  - arm64: pgtable: Ensure dirty bit is preserved across
    pte_wrprotect() (bsc#1180130).

  - arm64: pgtable: Fix pte_accessible() (bsc#1180130).

  - ASoC: ak4458: correct reset polarity (git-fixes).

  - ASoC: dapm: remove widget from dirty list on free
    (git-fixes).

  - ASoC: Intel: fix error code cnl_set_dsp_D0()
    (git-fixes).

  - ASoC: meson: axg-tdm-interface: fix loopback
    (git-fixes).

  - Bluetooth: revert: hci_h5: close serdev device and free
    hu in h5_close (git-fixes).

  - bnxt_en: Fix AER recovery (jsc#SLE-8371 bsc#1153274).

  - bpf: Do not leak memory in bpf getsockopt when optlen ==
    0 (bsc#1155518).

  - bpf: Fix helper bpf_map_peek_elem_proto pointing to
    wrong callback (bsc#1155518).

  - btrfs: send: fix invalid clone operations when cloning
    from the same file and root (bsc#1181511).

  - btrfs: send: fix wrong file path when there is an inode
    with a pending rmdir (bsc#1181237).

  - cachefiles: Drop superfluous readpages aops NULL check
    (git-fixes).

  - can: dev: prevent potential information leak in
    can_fill_info() (git-fixes).

  - can: vxcan: vxcan_xmit: fix use after free bug
    (git-fixes).

  - CDC-NCM: remove 'connected' log message (git-fixes).

  - clk: tegra30: Add hda clock default rates to clock
    driver (git-fixes).

  - crypto: asym_tpm: correct zero out potential secrets
    (git-fixes).

  - drivers/base/memory.c: indicate all memory blocks as
    removable (bsc#1180264).

  - drivers/perf: Fix kernel panic when rmmod PMU modules
    during perf sampling (bsc#1180848).

  - drivers/perf: hisi: Permit modular builds of HiSilicon
    uncore drivers (bsc#1180848). - Update config files. -
    supported.conf :

  - drm: Added orientation quirk for ASUS tablet model
    T103HAF (git-fixes).

  - drm/amd/display: Add missing pflip irq for dcn2.0
    (git-fixes).

  - drm/amd/display: Avoid MST manager resource leak
    (git-fixes).

  - drm/amd/display: dal_ddc_i2c_payloads_create can fail
    causing panic (git-fixes).

  - drm/amd/display: dchubbub p-state warning during surface
    planes switch (git-fixes).

  - drm/amd/display: Do not double-buffer DTO adjustments
    (git-fixes).

  - drm/amd/display: Do not invoke kgdb_breakpoint()
    unconditionally (git-fixes).

  - drm/amd/display: Fix memleak in
    amdgpu_dm_mode_config_init (git-fixes).

  - drm/amd/display: Free gamma after calculating legacy
    transfer function (git-fixes).

  - drm/amd/display: HDMI remote sink need mode validation
    for Linux (git-fixes).

  - drm/amd/display: Increase timeout for DP Disable
    (git-fixes).

  - drm/amd/display: Reject overlay plane configurations in
    multi-display scenarios (git-fixes).

  - drm/amd/display: remove useless if/else (git-fixes).

  - drm/amd/display: Retry AUX write when fail occurs
    (git-fixes).

  - drm/amd/display: Stop if retimer is not available
    (git-fixes).

  - drm/amd/display: update nv1x stutter latencies
    (git-fixes).

  - drm/amdgpu: add DID for navi10 blockchain SKU
    (git-fixes).

  - drm/amdgpu: correct the gpu reset handling for job !=
    NULL case (git-fixes).

  - drm/amdgpu/dc: Require primary plane to be enabled
    whenever the CRTC is (git-fixes).

  - drm/amdgpu: do not map BO in reserved region
    (git-fixes).

  - drm/amdgpu: fix a GPU hang issue when remove device
    (git-fixes).

  - drm/amdgpu: Fix bug in reporting voltage for CIK
    (git-fixes).

  - drm/amdgpu: Fix bug where DPM is not enabled after
    hibernate and resume (git-fixes).

  - drm/amdgpu: fix build_coefficients() argument
    (git-fixes).

  - drm/amdgpu: fix calltrace during kmd unload(v3)
    (git-fixes).

  - drm/amdgpu: increase atombios cmd timeout (git-fixes).

  - drm/amdgpu: increase the reserved VM size to 2MB
    (git-fixes).

  - drm/amdgpu: perform srbm soft reset always on SDMA
    resume (git-fixes).

  - drm/amdgpu/powerplay: fix AVFS handling with custom
    powerplay table (git-fixes).

  - drm/amdgpu/powerplay/smu7: fix AVFS handling with custom
    powerplay table (git-fixes).

  - drm/amdgpu: prevent double kfree ttm->sg (git-fixes).

  - drm/amdgpu/psp: fix psp gfx ctrl cmds (git-fixes).

  - drm/amdgpu/sriov add amdgpu_amdkfd_pre_reset in gpu
    reset (git-fixes).

  - drm/amdkfd: fix a memory leak issue (git-fixes).

  - drm/amdkfd: Fix leak in dmabuf import (git-fixes).

  - drm/amdkfd: fix restore worker race condition
    (git-fixes).

  - drm/amdkfd: Use same SQ prefetch setting as amdgpu
    (git-fixes).

  - drm/amd/pm: avoid false alarm due to confusing
    softwareshutdowntemp setting (git-fixes).

  - drm/aspeed: Fix Kconfig warning & subsequent build
    errors (bsc#1152472)

  - drm/aspeed: Fix Kconfig warning & subsequent build
    errors (git-fixes).

  - drm/atomic: put state on error path (git-fixes).

  - drm: bridge: dw-hdmi: Avoid resetting force in the
    detect function (bsc#1152472)

  - drm/bridge/synopsys: dsi: add support for non-continuous
    HS clock (git-fixes).

  - drm/brige/megachips: Add checking if
    ge_b850v3_lvds_init() is working correctly (git-fixes).

  - drm/dp_aux_dev: check aux_dev before use in
    (bsc#1152472)

  - drm/dp_aux_dev: check aux_dev before use in
    drm_dp_aux_dev_get_by_minor() (git-fixes).

  - drm/etnaviv: always start/stop scheduler in timeout
    processing (git-fixes).

  - drm/exynos: dsi: Remove bridge node reference in error
    handling path in probe function (git-fixes).

  - drm/gma500: fix double free of gma_connector
    (bsc#1152472) Backporting notes: &#9;* context changes

  - drm/gma500: fix double free of gma_connector
    (git-fixes).

  - drm/gma500: Fix out-of-bounds access to struct
    drm_device.vblank[] (git-fixes).

  - drm/i915: Avoid memory leak with more than 16
    workarounds on a list (git-fixes).

  - drm/i915: Break up error capture compression loops with
    cond_resched() (git-fixes).

  - drm/i915: Check for all subplatform bits (git-fixes).

  - drm/i915: clear the gpu reloc batch (git-fixes).

  - drm/i915: Correctly set SFC capability for video engines
    (bsc#1152489) Backporting notes: &#9;* context changes

  - drm/i915/display/dp: Compute the correct slice count for
    VDSC on DP (git-fixes).

  - drm/i915: Drop runtime-pm assert from vgpu io accessors
    (git-fixes).

  - drm/i915/dsi: Use unconditional msleep for the
    panel_on_delay when there is no reset-deassert
    MIPI-sequence (git-fixes).

  - drm/i915: Filter wake_flags passed to
    default_wake_function (git-fixes).

  - drm/i915: Fix mismatch between misplaced vma check and
    vma insert (git-fixes).

  - drm/i915: Force VT'd workarounds when running as a guest
    OS (git-fixes).

  - drm/i915/gt: Declare gen9 has 64 mocs entries!
    (git-fixes).

  - drm/i915/gt: Delay execlist processing for tgl
    (git-fixes).

  - drm/i915/gt: Free stale request on destroying the
    virtual engine (git-fixes).

  - drm/i915/gt: Prevent use of engine->wa_ctx after error
    (git-fixes).

  - drm/i915/gt: Program mocs:63 for cache eviction on gen9
    (git-fixes).

  - drm/i915/gvt: return error when failing to take the
    module reference (git-fixes).

  - drm/i915/gvt: Set ENHANCED_FRAME_CAP bit (git-fixes).

  - drm/i915: Handle max_bpc==16 (git-fixes).

  - drm/i915/selftests: Avoid passing a random 0 into ilog2
    (git-fixes).

  - drm/mcde: Fix handling of platform_get_irq() error
    (bsc#1152472)

  - drm/mcde: Fix handling of platform_get_irq() error
    (git-fixes).

  - drm/meson: dw-hdmi: Register a callback to disable the
    regulator (git-fixes).

  - drm/msm/a5xx: Always set an OPP supported hardware value
    (git-fixes).

  - drm/msm/a6xx: fix a potential overflow issue
    (git-fixes).

  - drm/msm/a6xx: fix gmu start on newer firmware
    (git-fixes).

  - drm/msm: add shutdown support for display
    platform_driver (git-fixes).

  - drm/msm: Disable preemption on all 5xx targets
    (git-fixes).

  - drm/msm/dpu: Add newline to printks (git-fixes).

  - drm/msm/dpu: Fix scale params in plane validation
    (git-fixes).

  - drm/msm/dsi_phy_10nm: implement PHY disabling
    (git-fixes).

  - drm/msm/dsi_pll_10nm: restore VCO rate during
    restore_state (git-fixes).

  - drm/msm: fix leaks if initialization fails (git-fixes).

  - drm/nouveau/bios: fix issue shadowing expansion ROMs
    (git-fixes).

  - drm/nouveau/debugfs: fix runtime pm imbalance on error
    (git-fixes).

  - drm/nouveau/dispnv50: fix runtime pm imbalance on error
    (git-fixes).

  - drm/nouveau: fix runtime pm imbalance on error
    (git-fixes).

  - drm/nouveau/i2c/gm200: increase width of aux semaphore
    owner fields (git-fixes).

  - drm/nouveau/kms/nv50-: fix case where notifier buffer is
    at offset 0 (git-fixes).

  - drm/nouveau/mem: guard against NULL pointer access in
    mem_del (git-fixes).

  - drm/nouveau/mmu: fix vram heap sizing (git-fixes).

  - drm/nouveau/nouveau: fix the start/end range for
    migration (git-fixes).

  - drm/nouveau/privring: ack interrupts the same way as RM
    (git-fixes).

  - drm/nouveau/svm: fail NOUVEAU_SVM_INIT ioctl on
    unsupported devices (git-fixes).

  - drm/omap: dmm_tiler: fix return error code in
    omap_dmm_probe() (git-fixes).

  - drm/omap: dss: Cleanup DSS ports on initialisation
    failure (git-fixes).

  - drm/omap: fix incorrect lock state (git-fixes).

  - drm/omap: fix possible object reference leak
    (git-fixes).

  - drm/panfrost: add amlogic reset quirk callback
    (git-fixes).

  - drm: rcar-du: Set primary plane zpos immutably at
    initializing (git-fixes).

  - drm/rockchip: Avoid uninitialized use of endpoint id in
    LVDS (bsc#1152472)

  - drm/rockchip: Avoid uninitialized use of endpoint id in
    LVDS (git-fixes).

  - drm/scheduler: Avoid accessing freed bad job
    (git-fixes).

  - drm/sun4i: dw-hdmi: fix error return code in
    sun8i_dw_hdmi_bind() (bsc#1152472)

  - drm/sun4i: frontend: Fix the scaler phase on A33
    (git-fixes).

  - drm/sun4i: frontend: Reuse the ch0 phase for RGB formats
    (git-fixes).

  - drm/sun4i: frontend: Rework a bit the phase data
    (git-fixes).

  - drm/sun4i: mixer: Extend regmap max_register
    (git-fixes).

  - drm/syncobj: Fix use-after-free (git-fixes).

  - drm/tegra: replace idr_init() by idr_init_base()
    (git-fixes).

  - drm/tegra: sor: Disable clocks on error in
    tegra_sor_init() (git-fixes).

  - drm/ttm: fix eviction valuable range check (git-fixes).

  - drm/tve200: Fix handling of platform_get_irq() error
    (bsc#1152472)

  - drm/tve200: Fix handling of platform_get_irq() error
    (git-fixes).

  - drm/tve200: Stabilize enable/disable (git-fixes).

  - drm/vc4: drv: Add error handding for bind (git-fixes).

  - e1000e: bump up timeout to wait when ME un-configures
    ULP mode (jsc#SLE-8100).

  - ehci: fix EHCI host controller initialization sequence
    (git-fixes).

  - ethernet: ucc_geth: fix use-after-free in
    ucc_geth_remove() (git-fixes).

  - Exclude Symbols.list again. Removing the exclude builds
    vanilla/linux-next builds. Fixes: 55877625c800
    ('kernel-binary.spec.in: Package the obj_install_dir as
    explicit filelist.')

  - firmware: imx: select SOC_BUS to fix firmware build
    (git-fixes).

  - floppy: reintroduce O_NDELAY fix (boo#1181018).

  - futex: Ensure the correct return value from
    futex_lock_pi() (bsc#1181349 bsc#1149032).

  - futex: Handle faults correctly for PI futexes
    (bsc#1181349 bsc#1149032).

  - futex: Provide and use pi_state_update_owner()
    (bsc#1181349 bsc#1149032).

  - futex: Remove needless goto's (bsc#1149032).

  - futex: Remove unused empty compat_exit_robust_list()
    (bsc#1149032).

  - futex: Replace pointless printk in fixup_owner()
    (bsc#1181349 bsc#1149032).

  - futex: Simplify fixup_pi_state_owner() (bsc#1181349
    bsc#1149032).

  - futex: Use pi_state_update_owner() in put_pi_state()
    (bsc#1181349 bsc#1149032).

  - HID: Ignore battery for Elan touchscreen on ASUS UX550
    (git-fixes).

  - HID: logitech-dj: add the G602 receiver (git-fixes).

  - HID: multitouch: Apply MT_QUIRK_CONFIDENCE quirk for
    multi-input devices (git-fixes).

  - HID: multitouch: do not filter mice nodes (git-fixes).

  - HID: multitouch: Enable multi-input for Synaptics
    pointstick/touchpad device (git-fixes).

  - HID: multitouch: Remove MT_CLS_WIN_8_DUAL (git-fixes).

  - HID: wacom: Constify attribute_groups (git-fixes).

  - HID: wacom: Correct NULL dereference on AES pen
    proximity (git-fixes).

  - HID: wacom: do not call hid_set_drvdata(hdev, NULL)
    (git-fixes).

  - HID: wacom: Fix memory leakage caused by kfifo_alloc
    (git-fixes).

  - hwmon: (pwm-fan) Ensure that calculation does not
    discard big period values (git-fixes).

  - i2c: bpmp-tegra: Ignore unknown I2C_M flags (git-fixes).

  - i2c: octeon: check correct size of maximum RECV_LEN
    packet (git-fixes).

  - ice: avoid premature Rx buffer reuse (jsc#SLE-7926).

  - ice, xsk: clear the status bits for the next_to_use
    descriptor (jsc#SLE-7926).

  - iio: ad5504: Fix setting power-down state (git-fixes).

  - iomap: fix WARN_ON_ONCE() from unprivileged users
    (bsc#1181494).

  - iommu/vt-d: Fix a bug for PDP check in prq_event_thread
    (bsc#1181217).

  - ionic: account for vlan tag len in rx buffer len
    (bsc#1167773).

  - kABI fixup for dwc3 introduction of DWC_usb32
    (git-fixes).

  - kprobes: tracing/kprobes: Fix to kill kprobes on initmem
    after boot (git fixes (kernel/kprobe)).

  - KVM: nVMX: Reload vmcs01 if getting vmcs12's pages fails
    (bsc#1181218).

  - KVM: s390: pv: Mark mm as protected after the set secure
    parameters and improve cleanup (jsc#SLE-7512
    bsc#1165545).

  - KVM: SVM: Initialize prev_ga_tag before use
    (bsc#1180809).

  - leds: trigger: fix potential deadlock with libata
    (git-fixes).

  - lib/genalloc: fix the overflow when size is too big
    (git-fixes).

  - lockd: do not use interval-based rebinding over TCP
    (for-next).

  - mac80211: check if atf has been disabled in
    __ieee80211_schedule_txq (git-fixes).

  - mac80211: do not drop tx nulldata packets on encrypted
    links (git-fixes).

  - md: fix a warning caused by a race between concurrent
    md_ioctl()s (for-next).

  - media: dvb-usb: Fix memory leak at error in
    dvb_usb_device_init() (bsc#1181104).

  - media: dvb-usb: Fix use-after-free access (bsc#1181104).

  - media: rc: ensure that uevent can be read directly after
    rc device register (git-fixes).

  - misdn: dsp: select CONFIG_BITREVERSE (git-fixes).

  - mmc: core: do not initialize block size from ext_csd if
    not present (git-fixes).

  - mmc: sdhci-xenon: fix 1.8v regulator stabilization
    (git-fixes).

  - mm: memcontrol: fix missing wakeup polling thread
    (bsc#1181584).

  - mm/vmalloc: Fix unlock order in s_stop() (git fixes
    (mm/vmalloc)).

  - module: delay kobject uevent until after module init
    call (bsc#1178631).

  - mt7601u: fix kernel crash unplugging the device
    (git-fixes).

  - mt7601u: fix rx buffer refcounting (git-fixes).

  - net/af_iucv: fix NULL pointer dereference on shutdown
    (bsc#1179567 LTC#190111).

  - net/af_iucv: set correct sk_protocol for child sockets
    (git-fixes).

  - net: fix proc_fs init handling in af_packet and tls
    (bsc#1154353).

  - net: hns3: fix a phy loopback fail issue (bsc#1154353).

  - net: hns3: remove a misused pragma packed (bsc#1154353).

  - net/mlx5e: ethtool, Fix restriction of autoneg with 56G
    (jsc#SLE-8464).

  - net: mscc: ocelot: allow offloading of bridge on top of
    LAG (git-fixes).

  - net/smc: cancel event worker during device removal
    (git-fixes).

  - net/smc: check for valid ib_client_data (git-fixes).

  - net/smc: fix cleanup for linkgroup setup failures
    (git-fixes).

  - net/smc: fix direct access to ib_gid_addr->ndev in
    smc_ib_determine_gid() (git-fixes).

  - net/smc: fix dmb buffer shortage (git-fixes).

  - net/smc: fix sleep bug in smc_pnet_find_roce_resource()
    (git-fixes).

  - net/smc: fix sock refcounting in case of termination
    (git-fixes).

  - net/smc: fix valid DMBE buffer sizes (git-fixes).

  - net/smc: no peer ID in CLC decline for SMCD (git-fixes).

  - net/smc: remove freed buffer from list (git-fixes).

  - net/smc: reset sndbuf_desc if freed (git-fixes).

  - net/smc: set rx_off for SMCR explicitly (git-fixes).

  - net/smc: switch smcd_dev_list spinlock to mutex
    (git-fixes).

  - net/smc: transfer fasync_list in case of fallback
    (git-fixes).

  - net: sunrpc: Fix 'snprintf' return value check in
    'do_xprt_debugfs' (for-next).

  - net: sunrpc: interpret the return value of kstrtou32
    correctly (for-next).

  - net: usb: qmi_wwan: add Quectel EM160R-GL (git-fixes).

  - net: vlan: avoid leaks on register_vlan_dev() failures
    (bsc#1154353).

  - NFC: fix possible resource leak (git-fixes).

  - NFC: fix resource leak when target index is invalid
    (git-fixes).

  - NFS4: Fix use-after-free in
    trace_event_raw_event_nfs4_set_lock (for-next).

  - nfs_common: need lock during iterate through the list
    (for-next).

  - nfsd4: readdirplus shouldn't return parent of export
    (git-fixes).

  - nfsd: Fix message level for normal termination
    (for-next).

  - NFS: nfs_delegation_find_inode_server must first
    reference the superblock (for-next).

  - NFS: nfs_igrab_and_active must first reference the
    superblock (for-next).

  - NFS/pNFS: Fix a leak of the layout 'plh_outstanding'
    counter (for-next).

  - NFS/pNFS: Fix a typo in ff_layout_resend_pnfs_read()
    (for-next).

  - NFS: switch nfsiod to be an UNBOUND workqueue
    (for-next).

  - NFSv4.2: condition READDIR's mask for security label
    based on LSM state (for-next).

  - NFSv4: Fix the alignment of page data in the
    getdeviceinfo reply (for-next).

  - nvme-rdma: avoid request double completion for
    concurrent nvme_rdma_timeout (bsc#1181161).

  - nvme-tcp: avoid request double completion for concurrent
    nvme_tcp_timeout (bsc#1181161).

  - platform/x86: i2c-multi-instantiate: Do not create
    platform device for INT3515 ACPI nodes (git-fixes).

  - platform/x86: ideapad-laptop: Disable touchpad_switch
    for ELAN0634 (git-fixes).

  - platform/x86: intel-vbtn: Drop HP Stream x360
    Convertible PC 11 from allow-list (git-fixes).

  - platform/x86: intel-vbtn: Fix SW_TABLET_MODE always
    reporting 1 on some HP x360 models (git-fixes).

  - PM: hibernate: flush swap writer after marking
    (git-fixes).

  - pNFS: Mark layout for return if return-on-close was not
    sent (git-fixes).

  - powerpc: Fix build error in paravirt.h (bsc#1181148
    ltc#190702).

  - powerpc/paravirt: Use is_kvm_guest() in
    vcpu_is_preempted() (bsc#1181148 ltc#190702).

  - powerpc: Refactor is_kvm_guest() declaration to new
    header (bsc#1181148 ltc#190702).

  - powerpc: Reintroduce is_kvm_guest() as a fast-path check
    (bsc#1181148 ltc#190702).

  - powerpc: Rename is_kvm_guest() to check_kvm_guest()
    (bsc#1181148 ltc#190702).

  - power: vexpress: add suppress_bind_attrs to true
    (git-fixes).

  - prom_init: enable verbose prints (bsc#1178142
    bsc#1180759).

  - ptrace: reintroduce usage of subjective credentials in
    ptrace_has_cap() (bsc#1163930).

  - ptrace: Set PF_SUPERPRIV when checking capability
    (bsc#1163930).

  - r8152: Add Lenovo Powered USB-C Travel Hub (git-fixes).

  - Revert 'nfsd4: support change_attr_type attribute'
    (for-next).

  - Revive usb-audio Keep Interface mixer (bsc#1181014).

  - rtmutex: Remove unused argument from
    rt_mutex_proxy_unlock() (bsc#1181349 bsc#1149032).

  - s390/cio: fix use-after-free in
    ccw_device_destroy_console (git-fixes).

  - s390/dasd: fix hanging device offline processing
    (bsc#1181169 LTC#190914).

  - s390/dasd: fix list corruption of lcu list (git-fixes).

  - s390/dasd: fix list corruption of pavgroup group list
    (git-fixes).

  - s390/dasd: prevent inconsistent LCU device data
    (git-fixes).

  - s390/kexec_file: fix diag308 subcode when loading crash
    kernel (git-fixes).

  - s390/qeth: consolidate online/offline code (git-fixes).

  - s390/qeth: do not raise NETDEV_REBOOT event from L3
    offline path (git-fixes).

  - s390/qeth: fix deadlock during recovery (git-fixes).

  - s390/qeth: fix L2 header access in
    qeth_l3_osa_features_check() (git-fixes).

  - s390/qeth: fix locking for discipline setup / removal
    (git-fixes).

  - s390/smp: perform initial CPU reset also for SMT
    siblings (git-fixes).

  - scsi: ibmvfc: Set default timeout to avoid crash during
    migration (bsc#1181425 ltc#188252).

  - scsi: lpfc: Enhancements to LOG_TRACE_EVENT for better
    readability (bsc#1180891).

  - scsi: lpfc: Fix auto sli_mode and its effect on
    CONFIG_PORT for SLI3 (bsc#1180891).

  - scsi: lpfc: Fix crash when a fabric node is released
    prematurely (bsc#1180891).

  - scsi: lpfc: Fix crash when nvmet transport calls
    host_release (bsc#1180891).

  - scsi: lpfc: Fix error log messages being logged
    following SCSI task mgnt (bsc#1180891).

  - scsi: lpfc: Fix FW reset action if I/Os are outstanding
    (bsc#1180891).

  - scsi: lpfc: Fix NVMe recovery after mailbox timeout
    (bsc#1180891).

  - scsi: lpfc: Fix PLOGI S_ID of 0 on pt2pt config
    (bsc#1180891).

  - scsi: lpfc: Fix target reset failing (bsc#1180891).

  - scsi: lpfc: Fix vport create logging (bsc#1180891).

  - scsi: lpfc: Implement health checking when aborting I/O
    (bsc#1180891).

  - scsi: lpfc: Prevent duplicate requests to unregister
    with cpuhp framework (bsc#1180891).

  - scsi: lpfc: Refresh ndlp when a new PRLI is received in
    the PRLI issue state (bsc#1180891).

  - scsi: lpfc: Simplify bool comparison (bsc#1180891).

  - scsi: lpfc: Update lpfc version to 12.8.0.7
    (bsc#1180891).

  - scsi: lpfc: Use the nvme-fc transport supplied timeout
    for LS requests (bsc#1180891).

  - scsi: qla2xxx: Fix description for parameter
    ql2xenforce_iocb_limit (bsc#1179142).

  - scsi: scsi_transport_srp: Do not block target in
    failfast state (bsc#1172355).

  - selftests/ftrace: Select an existing function in
    kprobe_eventname test (bsc#1179396 ltc#185738).

  - selftests: net: fib_tests: remove duplicate log test
    (git-fixes).

  - selftests/powerpc: Add a test of bad (out-of-range)
    accesses (bsc#1181158 ltc#190851).

  - selftests/powerpc: Add a test of spectre_v2 mitigations
    (bsc#1181158 ltc#190851).

  - selftests/powerpc: Ignore generated files (bsc#1181158
    ltc#190851).

  - selftests/powerpc: Move Hash MMU check to utilities
    (bsc#1181158 ltc#190851).

  - selftests/powerpc: Move set_dscr() into rfi_flush.c
    (bsc#1181158 ltc#190851).

  - selftests/powerpc: Only test lwm/stmw on big endian
    (bsc#1180412 ltc#190579).

  - selftests/powerpc: spectre_v2 test must be built 64-bit
    (bsc#1181158 ltc#190851).

  - serial: mvebu-uart: fix tx lost characters at power off
    (git-fixes).

  - spi: cadence: cache reference clock rate during probe
    (git-fixes).

  - SUNRPC: Clean up the handling of page padding in
    rpc_prepare_reply_pages() (for-next).

  - sunrpc: fix xs_read_xdr_buf for partial pages receive
    (for-next).

  - SUNRPC: rpc_wake_up() should wake up tasks in the
    correct order (for-next).

  - timers: Preserve higher bits of expiration on index
    calculation (bsc#1181318).

  - timers: Use only bucket expiry for base->next_expiry
    value (bsc#1181318).

  - udp: Prevent reuseport_select_sock from reading
    uninitialized socks (git-fixes).

  - USB: cdc-acm: blacklist another IR Droid device
    (git-fixes).

  - USB: cdc-wdm: Fix use after free in
    service_outstanding_interrupt() (git-fixes).

  - usb: dwc3: Add support for DWC_usb32 IP (git-fixes).

  - usb: dwc3: core: Properly default unspecified speed
    (git-fixes).

  - usb: dwc3: Update soft-reset wait polling rate
    (git-fixes).

  - USB: ehci: fix an interrupt calltrace error (git-fixes).

  - usb: gadget: aspeed: fix stop dma register setting
    (git-fixes).

  - usb: gadget: configfs: Fix use-after-free issue with
    udc_name (git-fixes).

  - usb: gadget: enable super speed plus (git-fixes).

  - usb: gadget: Fix spinlock lockup on
    usb_function_deactivate (git-fixes).

  - usb: gadget: function: printer: Fix a memory leak for
    interface descriptor (git-fixes).

  - USB: serial: option: add LongSung M5710 module support
    (git-fixes).

  - USB: serial: option: add Quectel EM160R-GL (git-fixes).

  - usb: typec: Fix copy paste error for NVIDIA alt-mode
    description (git-fixes).

  - usb: uas: Add PNY USB Portable SSD to unusual_uas
    (git-fixes).

  - usb: udc: core: Use lock when write to soft_connect
    (git-fixes).

  - USB: usblp: fix DMA to stack (git-fixes).

  - vfio iommu: Add dma available capability (bsc#1179572
    LTC#190110).

  - vfio/pci: Implement ioeventfd thread handler for
    contended memory lock (bsc#1181219).

  - vfio-pci: Use io_remap_pfn_range() for PCI IO memory
    (bsc#1181220).

  - video: fbdev: atmel_lcdfb: fix return error code in
    atmel_lcdfb_of_init() (git-fixes).

  - video: fbdev: fix OOB read in vga_8planes_imageblit()
    (git-fixes).

  - video: fbdev: pvr2fb: initialize variables (git-fixes).

  - video: fbdev: vga16fb: fix setting of pixclock because a
    pass-by-value error (git-fixes).

  - x86/apic: Fix x2apic enablement without interrupt
    remapping (bsc#1152489).

  - x86/cpu/amd: Call init_amd_zn() om Family 19h processors
    too (bsc#1181077).

  - x86/cpu/amd: Set __max_die_per_package on AMD
    (bsc#1152489).

  - x86/hyperv: Fix kexec panic/hang issues (bsc#1176831).

  - x86/kprobes: Restore BTF if the single-stepping is
    cancelled (bsc#1152489).

  - x86/topology: Make __max_die_per_package available
    unconditionally (bsc#1152489).

  - x86/xen: avoid warning in Xen pv guest with
    CONFIG_AMD_MEM_ENCRYPT enabled (bsc#1181335).

  - xen-blkfront: allow discard-* nodes to be optional
    (bsc#1181346).

  - xen/privcmd: allow fetching resource sizes
    (bsc#1065600).

  - xfs: show the proper user quota options (bsc#1181538).

  - xhci: make sure TRB is fully written before giving it to
    the controller (git-fixes).

  - xhci: tegra: Delay for disabling LFPS detector
    (git-fixes).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181584");
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3347");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/08");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.63.1.lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.63.1.lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.63.1") ) flag++;

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
