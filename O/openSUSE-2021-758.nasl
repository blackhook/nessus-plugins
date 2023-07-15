#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-758.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2019-18814",
    "CVE-2019-19769",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2020-27170",
    "CVE-2020-27171",
    "CVE-2020-27815",
    "CVE-2020-35519",
    "CVE-2020-36310",
    "CVE-2020-36311",
    "CVE-2020-36312",
    "CVE-2021-3428",
    "CVE-2021-3444",
    "CVE-2021-3483",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28038",
    "CVE-2021-28375",
    "CVE-2021-28660",
    "CVE-2021-28688",
    "CVE-2021-28950",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29264",
    "CVE-2021-29265",
    "CVE-2021-29647",
    "CVE-2021-30002"
  );

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2021-758)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 15 SP2 kernel RT was updated to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2021-3444: Fixed an issue with the bpf verifier
    which did not properly handle mod32 destination register
    truncation when the source register was known to be 0
    leading to out of bounds read (bsc#1184170).

  - CVE-2021-3428: Fixed an integer overflow in
    ext4_es_cache_extent (bsc#1173485).

  - CVE-2021-29647: Fixed an issue in qrtr_recvmsg which
    could have allowed attackers to obtain sensitive
    information from kernel memory because of a partially
    uninitialized data structure (bsc#1184192 ).

  - CVE-2021-29265: Fixed an issue in usbip_sockfd_store
    which could have allowed attackers to cause a denial of
    service due to race conditions during an update of the
    local and shared status (bsc#1184167).

  - CVE-2021-29264: Fixed an issue in the Freescale Gianfar
    Ethernet driver which could have allowed attackers to
    cause a system crash due to a calculation of negative
    fragment size (bsc#1184168).

  - CVE-2021-28972: Fixed a user-tolerable buffer overflow
    when writing a new device name to the driver from
    userspace, allowing userspace to write data to the
    kernel stack frame directly (bsc#1184198).

  - CVE-2021-28971: Fixed an issue in
    intel_pmu_drain_pebs_nhm which could have caused a
    system crash because the PEBS status in a PEBS record
    was mishandled (bsc#1184196 ).

  - CVE-2021-28964: Fixed a race condition in get_old_root
    which could have allowed attackers to cause a denial of
    service (bsc#1184193).

  - CVE-2021-28688: Fixed an issue introduced by XSA-365
    (bsc#1183646).

  - CVE-2021-28660: Fixed an out of bounds write in
    rtw_wx_set_scan (bsc#1183593 ).

  - CVE-2021-28375: Fixed an issue in
    fastrpc_internal_invoke which did not prevent user
    applications from sending kernel RPC messages
    (bsc#1183596).

  - CVE-2021-28038: Fixed an issue with the netback driver
    which was lacking necessary treatment of errors such as
    failed memory allocations (bsc#1183022).

  - CVE-2021-27365: Fixed an issue where an unprivileged
    user can send a Netlink message that is associated with
    iSCSI, and has a length up to the maximum length of a
    Netlink message (bsc#1182715).

  - CVE-2021-27364: Fixed an issue where an attacker could
    craft Netlink messages (bsc#1182717).

  - CVE-2021-27363: Fixed a kernel pointer leak which could
    have been used to determine the address of the
    iscsi_transport structure (bsc#1182716).

  - CVE-2020-35519: Fixed an out-of-bounds memory access was
    found in x25_bind (bsc#1183696).

  - CVE-2020-27815: Fixed an issue in JFS filesystem where
    could have allowed an attacker to execute code
    (bsc#1179454).

  - CVE-2020-27171: Fixed an off-by-one error affecting
    out-of-bounds speculation on pointer arithmetic, leading
    to side-channel attacks that defeat Spectre mitigations
    and obtain sensitive information from kernel memory
    (bsc#1183775).

  - CVE-2020-27170: Fixed potential side-channel attacks
    that defeat Spectre mitigations and obtain sensitive
    information from kernel memory (bsc#1183686).

  - CVE-2019-19769: Fixed a use-after-free in the
    perf_trace_lock_acquire function (bsc#1159280 ).

  - CVE-2019-18814: Fixed a use-after-free when
    aa_label_parse() fails in aa_audit_rule_init()
    (bsc#1156256).

  - CVE-2020-25670, CVE-2020-25671, CVE-2020-25672,
    CVE-2020-25673: Fixed multiple bugs in NFC subsytem
    (bsc#1178181).

  - CVE-2020-36311: Fixed a denial of service (soft lockup)
    by triggering destruction of a large SEV VM
    (bsc#1184511).

  - CVE-2021-29154: Fixed incorrect computation of branch
    displacements, allowing arbitrary code execution
    (bsc#1184391).

  - CVE-2021-30002: Fixed a memory leak for large arguments
    in video_usercopy (bsc#1184120).

  - CVE-2021-3483: Fixed a use-after-free in nosy.c
    (bsc#1184393).

  - CVE-2020-36310: Fixed infinite loop for certain nested
    page faults (bsc#1184512).

  - CVE-2020-36312: Fixed a memory leak upon a kmalloc
    failure (bsc#1184509 ).

  - CVE-2021-28950: Fixed an issue in fs/fuse/fuse_i.h due
    to a retry loop continually was finding the same bad
    inode (bsc#1184194).

The following non-security bugs were fixed :

  -
    0007-block-add-docs-for-gendisk-request_queue-refcount-h
    e.patch: (bsc#1171295, git fixes (block drivers)).

  -
    0008-block-revert-back-to-synchronous-request_queue-remo
    v.patch: (bsc#1171295, git fixes (block drivers)).

  - 0009-blktrace-fix-debugfs-use-after-free.patch:
    (bsc#1171295, git fixes (block drivers)). 

  - ACPI: bus: Constify is_acpi_node() and friends (part 2)
    (git-fixes).

  - ACPICA: Always create namespace nodes using
    acpi_ns_create_node() (git-fixes).

  - ACPICA: Enable sleep button on ACPI legacy wake
    (bsc#1181383).

  - ACPICA: Fix race in generic_serial_bus (I2C) and GPIO
    op_region parameter handling (git-fixes).

  - ACPI: scan: Rearrange memory allocation in
    acpi_device_add() (git-fixes).

  - ACPI: video: Add DMI quirk for GIGABYTE GB-BXBT-2807
    (git-fixes).

  - ACPI: video: Add missing callback back for Sony
    VPCEH3U1E (git-fixes).

  - ALSA: aloop: Fix initialization of controls (git-fixes).

  - ALSA: ctxfi: cthw20k2: fix mask on conf to allow 4 bits
    (git-fixes).

  - ALSA: hda: Avoid spurious unsol event handling during
    S3/S4 (git-fixes).

  - ALSA: hda: Drop the BATCH workaround for AMD controllers
    (git-fixes).

  - ALSA: hda: generic: Fix the micmute led init state
    (git-fixes).

  - ALSA: hda/hdmi: Cancel pending works before suspend
    (git-fixes).

  - ALSA: hda/realtek: Add quirk for Clevo NH55RZQ
    (git-fixes).

  - ALSA: hda/realtek: Add quirk for Intel NUC 10
    (git-fixes).

  - ALSA: hda/realtek: Apply dual codec quirks for MSI
    Godlike X570 board (git-fixes).

  - ALSA: hda/realtek: Apply headset-mic quirks for Xiaomi
    Redmibook Air (git-fixes).

  - ALSA: hda/realtek: apply pin quirk for XiaomiNotebook
    Pro (git-fixes).

  - ALSA: hda/realtek: Enable headset mic of Acer SWIFT with
    ALC256 (git-fixes).

  - ALSA: hda/realtek: fix a determine_headset_type issue
    for a Dell AIO (git-fixes).

  - ALSA: hda/realtek: Fix speaker amp setup on Acer Aspire
    E1 (git-fixes).

  - ALSA: usb: Add Plantronics C320-M USB ctrl msg delay
    quirk (bsc#1182552).

  - ALSA: usb-audio: Allow modifying parameters with
    succeeding hw_params calls (bsc#1182552).

  - ALSA: usb-audio: Apply sample rate quirk to Logitech
    Connect (git-fixes).

  - ALSA: usb-audio: Apply the control quirk to Plantronics
    headsets (bsc#1182552).

  - ALSA: usb-audio: Disable USB autosuspend properly in
    setup_disable_autosuspend() (bsc#1182552).

  - ALSA: usb-audio: Do not abort even if the clock rate
    differs (bsc#1182552).

  - ALSA: usb-audio: Drop bogus dB range in too low level
    (bsc#1182552).

  - ALSA: usb-audio: Fix 'cannot get freq eq' errors on Dell
    AE515 sound bar (bsc#1182552).

  - ALSA: usb-audio: fix NULL ptr dereference in
    usb_audio_probe (bsc#1182552).

  - ALSA: usb-audio: Fix 'RANGE setting not yet supported'
    errors (git-fixes).

  - ALSA: usb-audio: fix use after free in
    usb_audio_disconnect (bsc#1182552).

  - ALSA: usb-audio: Skip the clock selector inquiry for
    single connections (git-fixes).

  - ALSA: usb: Use DIV_ROUND_UP() instead of open-coding it
    (git-fixes).

  - amd/amdgpu: Disable VCN DPG mode for Picasso
    (git-fixes).

  - apparmor: check/put label on
    apparmor_sk_clone_security() (git-fixes).

  - appletalk: Fix skb allocation size in loopback case
    (git-fixes).

  - arm64: make STACKPROTECTOR_PER_TASK configurable
    (bsc#1181862).

  - ASoC: ak4458: Add MODULE_DEVICE_TABLE (git-fixes).

  - ASoC: ak5558: Add MODULE_DEVICE_TABLE (git-fixes).

  - ASoC: cs42l42: Always wait at least 3ms after reset
    (git-fixes).

  - ASoC: cs42l42: Do not enable/disable regulator at Bias
    Level (git-fixes).

  - ASoC: cs42l42: Fix Bitclock polarity inversion
    (git-fixes).

  - ASoC: cs42l42: Fix channel width support (git-fixes).

  - ASoC: cs42l42: Fix mixer volume control (git-fixes).

  - ASoC: cygnus: fix for_each_child.cocci warnings
    (git-fixes).

  - ASoC: es8316: Simplify adc_pga_gain_tlv table
    (git-fixes).

  - ASoC: fsl_esai: Fix TDM slot setup for I2S mode
    (git-fixes).

  - ASoC: fsl_ssi: Fix TDM slot setup for I2S mode
    (git-fixes).

  - ASoC: Intel: Add DMI quirk table to
    soc_intel_is_byt_cr() (git-fixes).

  - ASoC: intel: atom: Remove 44100 sample-rate from the
    media and deep-buffer DAI descriptions (git-fixes).

  - ASoC: intel: atom: Stop advertising non working S24LE
    support (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for ARCHOS Cesium
    140 (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for the Acer One
    S1002 tablet (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for the Estar
    Beauty HD MID 7316R tablet (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for the Voyo Winpad
    A15 tablet (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Fix HP Pavilion x2 10-p0XX
    OVCD current threshold (git-fixes).

  - ASoC: Intel: bytcr_rt5651: Add quirk for the Jumper
    EZpad 7 tablet (git-fixes).

  - ASoC: max98373: Added 30ms turn on/off time delay
    (git-fixes).

  - ASoC: rt5640: Fix dac- and adc- vol-tlv values being off
    by a factor of 10 (git-fixes).

  - ASoC: rt5651: Fix dac- and adc- vol-tlv values being off
    by a factor of 10 (git-fixes).

  - ASoC: rt5670: Add emulated 'DAC1 Playback Switch'
    control (git-fixes).

  - ASoC: rt5670: Remove ADC vol-ctrl mute bits poking from
    Sto1 ADC mixer settings (git-fixes).

  - ASoC: rt5670: Remove 'HP Playback Switch' control
    (git-fixes).

  - ASoC: rt5670: Remove 'OUT Channel Switch' control
    (git-fixes).

  - ASoC: sgtl5000: set DAP_AVC_CTRL register to correct
    default value on probe (git-fixes).

  - ASoC: simple-card-utils: Do not handle device clock
    (git-fixes).

  - ASoC: sunxi: sun4i-codec: fill ASoC card owner
    (git-fixes).

  - ASoC: wm8960: Fix wrong bclk and lrclk with pll enabled
    for some chips (git-fixes).

  - ath10k: fix wmi mgmt tx queue full due to race condition
    (git-fixes).

  - ath10k: hold RCU lock when calling
    ieee80211_find_sta_by_ifaddr() (git-fixes).

  - ath9k: fix transmitting to stations in dynamic SMPS mode
    (git-fixes).

  - atl1c: fix error return code in atl1c_probe()
    (git-fixes).

  - atl1e: fix error return code in atl1e_probe()
    (git-fixes).

  - batman-adv: initialize 'struct
    batadv_tvlv_tt_vlan_data'->reserved field (git-fixes).

  - binfmt_misc: fix possible deadlock in bm_register_write
    (git-fixes).

  - binfmt_misc: fix possible deadlock in bm_register_write
    (git-fixes).

  -
    blktrace-annotate-required-lock-on-do_blk_trace_setu.pat
    ch: (bsc#1171295).

  -
    blktrace-Avoid-sparse-warnings-when-assigning-q-blk_.pat
    ch: (bsc#1171295).

  -
    blktrace-break-out-of-blktrace-setup-on-concurrent-c.pat
    ch: (bsc#1171295).

  -
    block-clarify-context-for-refcount-increment-helpers.pat
    ch: (bsc#1171295).

  - block: rsxx: fix error return code of rsxx_pci_probe()
    (git-fixes).

  - Bluetooth: Fix NULL pointer dereference in
    amp_read_loc_assoc_final_data (git-fixes).

  - Bluetooth: hci_h5: Set HCI_QUIRK_SIMULTANEOUS_DISCOVERY
    for btrtl (git-fixes).

  - bnxt_en: reliably allocate IRQ table on reset to avoid
    crash (jsc#SLE-8371 bsc#1153274).

  - bpf: Add sanity check for upper ptr_limit (bsc#1183686
    bsc#1183775).

  - bpf: Avoid warning when re-casting __bpf_call_base into
    __bpf_call_base_args (bsc#1155518).

  - bpf: Declare __bpf_free_used_maps() unconditionally
    (bsc#1155518).

  - bpf: Do not do bpf_cgroup_storage_set() for kuprobe/tp
    programs (bsc#1155518).

  - bpf: Fix 32 bit src register truncation on div/mod
    (bsc#1184170).

  - bpf_lru_list: Read double-checked variable once without
    lock (bsc#1155518).

  - bpf: Remove MTU check in __bpf_skb_max_len
    (bsc#1155518).

  - bpf: Simplify alu_limit masking for pointer arithmetic
    (bsc#1183686 bsc#1183775).

  - bpf,x64: Pad NOPs to make images converge more easily
    (bsc#1178163).

  - brcmfmac: Add DMI nvram filename quirk for Predia Basic
    tablet (git-fixes).

  - brcmfmac: Add DMI nvram filename quirk for Voyo winpad
    A15 tablet (git-fixes).

  - brcmfmac: clear EAP/association status bits on linkdown
    events (git-fixes).

  - btrfs: abort the transaction if we fail to inc ref in
    btrfs_copy_root (bsc#1184217).

  - btrfs: always pin deleted leaves when there are active
    tree mod log users (bsc#1184224).

  - btrfs: fix exhaustion of the system chunk array due to
    concurrent allocations (bsc#1183386).

  - btrfs: fix extent buffer leak on failure to copy root
    (bsc#1184218).

  - btrfs: fix race when cloning extent buffer during rewind
    of an old root (bsc#1184193).

  - btrfs: fix stale data exposure after cloning a hole with
    NO_HOLES enabled (bsc#1184220).

  - btrfs: fix subvolume/snapshot deletion not triggered on
    mount (bsc#1184219).

  - bus: omap_l3_noc: mark l3 irqs as IRQF_NO_THREAD
    (git-fixes).

  - bus: ti-sysc: Fix warning on unbind if reset is not
    deasserted (git-fixes).

  - can: c_can: move runtime PM enable/disable to
    c_can_platform (git-fixes).

  - can: c_can_pci: c_can_pci_remove(): fix use-after-free
    (git-fixes).

  - can: flexcan: assert FRZ bit in flexcan_chip_freeze()
    (git-fixes).

  - can: flexcan: enable RX FIFO after FRZ/HALT valid
    (git-fixes).

  - can: flexcan: flexcan_chip_freeze(): fix chip freeze for
    missing bitrate (git-fixes).

  - can: flexcan: invoke flexcan_chip_freeze() to enter
    freeze mode (git-fixes).

  - can: m_can: m_can_do_rx_poll(): fix extraneous msg loss
    warning (git-fixes).

  - can: peak_usb: add forgotten supported devices
    (git-fixes).

  - can: peak_usb: Revert 'can: peak_usb: add forgotten
    supported devices' (git-fixes).

  - can: skb: can_skb_set_owner(): fix ref counting if
    socket was closed before setting skb ownership
    (git-fixes).

  - cdc-acm: fix BREAK rx code path adding necessary calls
    (git-fixes).

  - certs: Fix blacklist flag type confusion (git-fixes).

  - cifs: change noisy error message to FYI (bsc#1181507).

  - cifs: check pointer before freeing (bsc#1183534).

  - cifs_debug: use %pd instead of messing with ->d_name
    (bsc#1181507).

  - cifs: do not send close in compound create+close
    requests (bsc#1181507).

  - cifs: New optype for session operations (bsc#1181507).

  - cifs: print MIDs in decimal notation (bsc#1181507).

  - cifs: return proper error code in statfs(2)
    (bsc#1181507).

  - cifs: Tracepoints and logs for tracing credit changes
    (bsc#1181507).

  - clk: fix invalid usage of list cursor in register
    (git-fixes).

  - clk: fix invalid usage of list cursor in unregister
    (git-fixes).

  - clk: socfpga: fix iomem pointer cast on 64-bit
    (git-fixes).

  - completion: Drop init_completion define (git-fixes).

  - configfs: fix a use-after-free in __configfs_open_file
    (git-fixes).

  - config: net: freescale: change xgmac-mdio to built-in
    References: bsc#1183015,bsc#1182595

  - crypto: aesni - prevent misaligned buffers on the stack
    (git-fixes).

  - crypto: arm64/sha - add missing module aliases
    (git-fixes).

  - crypto: bcm - Rename struct device_private to
    bcm_device_private (git-fixes).

  - crypto: Kconfig - CRYPTO_MANAGER_EXTRA_TESTS requires
    the manager (git-fixes).

  - crypto: tcrypt - avoid signed overflow in byte count
    (git-fixes).

  - Delete
    patches.suse/sched-Reenable-interrupts-in-do_sched_yield
    .patch (bsc#1183530) 

  - drivers/misc/vmw_vmci: restrict too big queue size in
    qp_host_alloc_queue (git-fixes).

  - drivers: video: fbcon: fix NULL dereference in
    fbcon_cursor() (git-fixes).

  - drm/amd/display: Guard against NULL pointer deref when
    get_i2c_info fails (git-fixes).

  - drm/amdgpu: Add check to prevent IH overflow
    (git-fixes).

  - drm/amdgpu: check alignment on CPU page for bo map
    (git-fixes).

  - drm/amdgpu: fix offset calculation in
    amdgpu_vm_bo_clear_mappings() (git-fixes).

  - drm/amdgpu: fix parameter error of RREG32_PCIE() in
    amdgpu_regs_pcie (git-fixes).

  - drm/amdkfd: Put ACPI table after using it (bsc#1152489)
    Backporting notes: &#9;* context changes

  - drm/amd/powerplay: fix spelling mistake
    'smu_state_memroy_block' -> (bsc#1152489) Backporting
    notes: &#9;* rename amd/pm to amd/powerplay &#9;*
    context changes

  - drm/compat: Clear bounce structures (git-fixes).

  - drm/hisilicon: Fix use-after-free (git-fixes).

  - drm/i915: Fix invalid access to ACPI _DSM objects
    (bsc#1184074).

  - drm/i915: Reject 446-480MHz HDMI clock on GLK
    (git-fixes).

  - drm/mediatek: Fix aal size config (bsc#1152489) 

  - drm: meson_drv add shutdown function (git-fixes).

  - drm/msm/a5xx: Remove overwriting A5XX_PC_DBG_ECO_CNTL
    register (git-fixes).

  - drm/msm/adreno: a5xx_power: Do not apply A540 lm_setup
    to other GPUs (git-fixes).

  - drm/msm/dsi: Correct io_start for MSM8994 (20nm PHY)
    (git-fixes).

  - drm/msm: Fix races managing the OOB state for timestamp
    vs (bsc#1152489) 

  - drm/msm: fix shutdown hook in case GPU components failed
    to bind (git-fixes).

  - drm/msm: Fix use-after-free in msm_gem with carveout
    (bsc#1152489) 

  - drm/msm: Fix WARN_ON() splat in _free_object()
    (bsc#1152489) 

  - drm/msm/gem: Add obj->lock wrappers (bsc#1152489) 

  - drm/msm: Ratelimit invalid-fence message (git-fixes).

  - drm/msm: Set drvdata to NULL when msm_drm_init() fails
    (git-fixes).

  - drm/nouveau: bail out of nouveau_channel_new if channel
    init fails (bsc#1152489) 

  - drm/nouveau/kms: handle mDP connectors (git-fixes).

  - drm/panfrost: Do not corrupt the queue mutex on
    open/close (bsc#1152472) 

  - drm/panfrost: Fix job timeout handling (bsc#1152472) 

  - drm/panfrost: Remove unused variables in
    panfrost_job_close() (bsc#1152472)

  - drm/radeon: fix AGP dependency (git-fixes).

  - drm: rcar-du: Fix crash when using LVDS1 clock for CRTC
    (bsc#1152489) 

  - drm/sched: Cancel and flush all outstanding jobs before
    finish (git-fixes).

  - drm/sun4i: tcon: fix inverted DCLK polarity
    (bsc#1152489) 

  - drm/tegra: sor: Grab runtime PM reference across reset
    (git-fixes).

  - drm/vc4: hdmi: Restore cec physical address on reconnect
    (bsc#1152472) 

  - efi: use 32-bit alignment for efi_guid_t literals
    (git-fixes).

  - enetc: Fix reporting of h/w packet counters (git-fixes).

  - epoll: check for events when removing a timed out thread
    from the wait queue (git-fixes).

  - ethernet: alx: fix order of calls on resume (git-fixes).

  - exec: Move would_dump into flush_old_exec (git-fixes).

  - exfat: add missing MODULE_ALIAS_FS() (bsc#1182989).

  - exfat: add the dummy mount options to be backward
    compatible with staging/exfat (bsc#1182989).

  - extcon: Add stubs for extcon_register_notifier_all()
    functions (git-fixes).

  - extcon: Fix error handling in extcon_dev_register
    (git-fixes).

  - fbdev: aty: SPARC64 requires FB_ATY_CT (git-fixes).

  - firmware/efi: Fix a use after bug in
    efi_mem_reserve_persistent (git-fixes).

  - flow_dissector: fix byteorder of dissected ICMP ID
    (bsc#1154353).

  - fsl/fman: check dereferencing NULL pointer (git-fixes).

  - fsl/fman: fix dereference null return value (git-fixes).

  - fsl/fman: fix eth hash table allocation (git-fixes).

  - fsl/fman: fix unreachable code (git-fixes).

  - fsl/fman: use 32-bit unsigned integer (git-fixes).

  - fuse: fix bad inode (bsc#1184211).

  - fuse: fix live lock in fuse_iget() (bsc#1184211).

  - fuse: verify write return (git-fixes).

  - gcc-plugins: drop support for GCC <= 4.7 (bcs#1181862).

  - gcc-plugins: make it possible to disable
    CONFIG_GCC_PLUGINS again (bcs#1181862).

  - gcc-plugins: simplify GCC plugin-dev capability test
    (bsc#1181862).

  - gianfar: Account for Tx PTP timestamp in the skb
    headroom (git-fixes).

  - gianfar: Fix TX timestamping with a stacked DSA driver
    (git-fixes).

  - gianfar: Handle error code at MAC address change
    (git-fixes).

  - gianfar: Replace skb_realloc_headroom with skb_cow_head
    for PTP (git-fixes).

  - Goodix Fingerprint device is not a modem (git-fixes).

  - gpiolib: acpi: Add missing IRQF_ONESHOT (git-fixes).

  - gpio: pca953x: Set IRQ type when handle Intel Galileo
    Gen 2 (git-fixes).

  - gpio: zynq: fix reference leak in zynq_gpio functions
    (git-fixes).

  - HID: i2c-hid: Add I2C_HID_QUIRK_NO_IRQ_AFTER_RESET for
    ITE8568 EC on Voyo Winpad A15 (git-fixes).

  - HID: mf: add support for 0079:1846 Mayflash/Dragonrise
    USB Gamecube Adapter (git-fixes).

  - HSI: Fix PM usage counter unbalance in ssi_hw_init
    (git-fixes).

  - hwmon: (ina3221) Fix PM usage counter unbalance in
    ina3221_write_enable (git-fixes).

  - i2c: rcar: faster irq code to minimize HW race condition
    (git-fixes).

  - i2c: rcar: optimize cacheline to minimize HW race
    condition (git-fixes).

  - i40e: Fix parameters in aq_get_phy_register()
    (jsc#SLE-8025).

  - i40e: Fix sparse error: 'vsi->netdev' could be null
    (jsc#SLE-8025).

  - iavf: Fix incorrect adapter get in iavf_resume
    (git-fixes).

  - iavf: use generic power management (git-fixes).

  - ibmvnic: add comments for spinlock_t definitions
    (bsc#1183871 ltc#192139).

  - ibmvnic: always store valid MAC address (bsc#1182011
    ltc#191844).

  - ibmvnic: avoid multiple line dereference (bsc#1183871
    ltc#192139).

  - ibmvnic: fix block comments (bsc#1183871 ltc#192139).

  - ibmvnic: fix braces (bsc#1183871 ltc#192139).

  - ibmvnic: fix miscellaneous checks (bsc#1183871
    ltc#192139).

  - ibmvnic: Fix possibly uninitialized old_num_tx_queues
    variable warning (jsc#SLE-17268).

  - ibmvnic: merge do_change_param_reset into do_reset
    (bsc#1183871 ltc#192139).

  - ibmvnic: prefer strscpy over strlcpy (bsc#1183871
    ltc#192139).

  - ibmvnic: prefer 'unsigned long' over 'unsigned long int'
    (bsc#1183871 ltc#192139).

  - ibmvnic: remove excessive irqsave (bsc#1182485
    ltc#191591).

  - ibmvnic: remove unnecessary rmb() inside ibmvnic_poll
    (bsc#1183871 ltc#192139).

  - ibmvnic: remove unused spinlock_t stats_lock definition
    (bsc#1183871 ltc#192139).

  - ibmvnic: rework to ensure SCRQ entry reads are properly
    ordered (bsc#1183871 ltc#192139).

  - ibmvnic: simplify reset_long_term_buff function
    (bsc#1183023 ltc#191791).

  - ibmvnic: substitute mb() with dma_wmb() for send_*crq*
    functions (bsc#1183023 ltc#191791).

  - ice: fix memory leak if register_netdev_fails
    (git-fixes).

  - ice: fix memory leak in ice_vsi_setup (git-fixes).

  - ice: Fix state bits on LLDP mode switch (jsc#SLE-7926).

  - ice: remove DCBNL_DEVRESET bit from PF state
    (jsc#SLE-7926).

  - ice: renegotiate link after FW DCB on (jsc#SLE-8464).

  - ice: report correct max number of TCs (jsc#SLE-7926).

  - ice: update the number of available RSS queues
    (jsc#SLE-7926).

  - igc: Fix igc_ptp_rx_pktstamp() (bsc#1160634).

  - iio: adc: ad7949: fix wrong ADC result due to incorrect
    bit mask (git-fixes).

  - iio:adc:qcom-spmi-vadc: add default scale to
    LR_MUX2_BAT_ID channel (git-fixes).

  - iio: adis16400: Fix an error code in
    adis16400_initial_setup() (git-fixes).

  - iio: gyro: mpu3050: Fix error handling in
    mpu3050_trigger_handler (git-fixes).

  - iio: hid-sensor-humidity: Fix alignment issue of
    timestamp channel (git-fixes).

  - iio: hid-sensor-prox: Fix scale not correct issue
    (git-fixes).

  - iio: hid-sensor-temperature: Fix issues of timestamp
    channel (git-fixes).

  - include/linux/sched/mm.h: use rcu_dereference in
    in_vfork() (git-fixes).

  - Input: applespi - do not wait for responses to commands
    indefinitely (git-fixes).

  - Input: elantech - fix protocol errors for some
    trackpoints in SMBus mode (git-fixes).

  - Input: i8042 - add ASUS Zenbook Flip to noselftest list
    (git-fixes).

  - Input: raydium_ts_i2c - do not send zero length
    (git-fixes).

  - Input: xpad - add support for PowerA Enhanced Wired
    Controller for Xbox Series X|S (git-fixes).

  - iommu/amd: Fix sleeping in atomic in
    increase_address_space() (bsc#1183277).

  - iommu/intel: Fix memleak in intel_irq_remapping_alloc
    (bsc#1183278).

  - iommu/qcom: add missing put_device() call in
    qcom_iommu_of_xlate() (bsc#1183637).

  - iommu/vt-d: Add get_domain_info() helper (bsc#1183279).

  - iommu/vt-d: Avoid panic if iommu init fails in tboot
    system (bsc#1183280).

  - iommu/vt-d: Correctly check addr alignment in
    qi_flush_dev_iotlb_pasid() (bsc#1183281).

  - iommu/vt-d: Do not use flush-queue when caching-mode is
    on (bsc#1183282).

  - iommu/vt-d: Fix general protection fault in
    aux_detach_device() (bsc#1183283).

  - iommu/vt-d: Fix ineffective devTLB invalidation for
    subdevices (bsc#1183284).

  - iommu/vt-d: Fix unaligned addresses for
    intel_flush_svm_range_dev() (bsc#1183285).

  - iommu/vt-d: Move intel_iommu info from struct intel_svm
    to struct intel_svm_dev (bsc#1183286).

  - ionic: linearize tso skb with too many frags
    (bsc#1167773).

  - kABI: powerpc/pmem: Include pmem prototypes (bsc#1113295
    git-fixes).

  - kbuild: add dummy toolchains to enable all cc-option
    etc. in Kconfig (bcs#1181862).

  - kbuild: change *FLAGS_<basetarget>.o to take the path
    relative to $(obj) (bcs#1181862).

  - kbuild: dummy-tools, fix inverted tests for gcc
    (bcs#1181862).

  - kbuild: dummy-tools, support MPROFILE_KERNEL checks for
    ppc (bsc#1181862).

  - kbuild: Fail if gold linker is detected (bcs#1181862).

  - kbuild: improve cc-option to clean up all temporary
    files (bsc#1178330).

  - kbuild: include scripts/Makefile.* only when relevant
    CONFIG is enabled (bcs#1181862).

  - kbuild: simplify GCC_PLUGINS enablement in
    dummy-tools/gcc (bcs#1181862).

  - kbuild: stop filtering out $(GCC_PLUGINS_CFLAGS) from
    cc-option base (bcs#1181862).

  - kbuild: use -S instead of -E for precise cc-option test
    in Kconfig (bsc#1178330).

  - kconfig: introduce m32-flag and m64-flag (bcs#1181862).

  - KVM: nVMX: Properly handle userspace interrupt window
    request (bsc#1183427).

  - KVM: SVM: Clear the CR4 register on reset (bsc#1183252).

  - KVM: x86: Add helpers to perform CPUID-based guest
    vendor check (bsc#1183445). 

  - KVM: x86: Add RIP to the kvm_entry, i.e. VM-Enter,
    tracepoint Needed as a dependency of 0b40723a827 ('kvm:
    tracing: Fix unmatched kvm_entry and kvm_exit events',
    bsc#1182770).

  - KVM: x86: Allow guests to see MSR_IA32_TSX_CTRL even if
    tsx=off (bsc#1183287).

  - KVM: x86: do not reset microcode version on INIT or
    RESET (bsc#1183412).

  - KVM x86: Extend AMD specific guest behavior to Hygon
    virtual CPUs (bsc#1183447).

  - KVM: x86: list MSR_IA32_UCODE_REV as an emulated MSR
    (bsc#1183369).

  - KVM: x86: Return -E2BIG when KVM_GET_SUPPORTED_CPUID
    hits max entries (bsc#1183428).

  - KVM: x86: Set so called 'reserved CR3 bits in LM mask'
    at vCPU reset (bsc#1183288).

  - libbpf: Clear map_info before each
    bpf_obj_get_info_by_fd (bsc#1155518).

  - libbpf: Fix BTF dump of pointer-to-array-of-struct
    (bsc#1155518).

  - libbpf: Fix INSTALL flag order (bsc#1155518).

  - libbpf: Use SOCK_CLOEXEC when opening the netlink socket
    (bsc#1155518).

  - lib/syscall: fix syscall registers retrieval on 32-bit
    platforms (git-fixes).

  - locking/mutex: Fix non debug version of
    mutex_lock_io_nested() (git-fixes).

  -
    loop-be-paranoid-on-exit-and-prevent-new-additions-r.pat
    ch: (bsc#1171295).

  - mac80211: choose first enabled channel for monitor
    (git-fixes).

  - mac80211: fix double free in ibss_leave (git-fixes).

  - mac80211: fix rate mask reset (git-fixes).

  - mac80211: fix TXQ AC confusion (git-fixes).

  - mdio: fix mdio-thunder.c dependency & build error
    (git-fixes).

  - media: cros-ec-cec: do not bail on device_init_wakeup
    failure (git-fixes).

  - media: cx23885: add more quirks for reset DMA on some
    AMD IOMMU (git-fixes).

  - media: mceusb: Fix potential out-of-bounds shift
    (git-fixes).

  - media: mceusb: sanity check for prescaler value
    (git-fixes).

  - media: rc: compile rc-cec.c into rc-core (git-fixes).

  - media: usbtv: Fix deadlock on suspend (git-fixes).

  - media: uvcvideo: Allow entities with no pads
    (git-fixes).

  - media: v4l2-ctrls.c: fix shift-out-of-bounds in
    std_validate (git-fixes).

  - media: v4l: vsp1: Fix bru NULL pointer access
    (git-fixes).

  - media: v4l: vsp1: Fix uif NULL pointer access
    (git-fixes).

  - media: vicodec: add missing v4l2_ctrl_request_hdl_put()
    (git-fixes).

  - misc: eeprom_93xx46: Add quirk to support Microchip
    93LC46B eeprom (git-fixes).

  - misc: fastrpc: restrict user apps from sending kernel
    RPC messages (git-fixes).

  - misc/pvpanic: Export module FDT device table
    (git-fixes).

  - misc: rtsx: init of rts522a add OCP power off when no
    card is present (git-fixes).

  - mISDN: fix crash in fritzpci (git-fixes).

  - mmc: core: Fix partition switch time for eMMC
    (git-fixes).

  - mmc: cqhci: Fix random crash when remove mmc module/card
    (git-fixes).

  - mmc: mxs-mmc: Fix a resource leak in an error handling
    path in 'mxs_mmc_probe()' (git-fixes).

  - mmc: sdhci-esdhc-imx: fix kernel panic when remove
    module (git-fixes).

  - mmc: sdhci-of-dwcmshc: set
    SDHCI_QUIRK2_PRESET_VALUE_BROKEN (git-fixes).

  - mm: hugetlbfs: fix cannot migrate the fallocated HugeTLB
    page (git-fixes).

  - mm, numa: fix bad pmd by atomically check for
    pmd_trans_huge when marking page tables prot_numa
    (bsc#1168777).

  - mount: fix mounting of detached mounts onto targets that
    reside on shared mounts (git-fixes).

  - mt76: dma: do not report truncated frames to mac80211
    (git-fixes).

  - mwifiex: pcie: skip cancel_work_sync() on reset failure
    path (git-fixes).

  - net: arc_emac: Fix memleak in arc_mdio_probe
    (git-fixes).

  - net: atheros: switch from 'pci_' to 'dma_' API
    (git-fixes).

  - net: b44: fix error return code in b44_init_one()
    (git-fixes).

  - net: bonding: fix error return code of bond_neigh_init()
    (bsc#1154353).

  - net: cdc-phonet: fix data-interface release on probe
    failure (git-fixes).

  - net: core: introduce __netdev_notify_peers (bsc#1183871
    ltc#192139).

  - netdevsim: init u64 stats for 32bit hardware
    (git-fixes).

  - net: dsa: rtl8366: Fix VLAN semantics (git-fixes).

  - net: dsa: rtl8366: Fix VLAN set-up (git-fixes).

  - net: dsa: rtl8366rb: Support all 4096 VLANs (git-fixes).

  - net: enic: Cure the enic api locking trainwreck
    (git-fixes).

  - net: ethernet: aquantia: Fix wrong return value
    (git-fixes).

  - net: ethernet: cavium: octeon_mgmt: use phy_start and
    phy_stop (git-fixes).

  - net: ethernet: ibm: ibmvnic: Fix some kernel-doc
    misdemeanours (bsc#1183871 ltc#192139).

  - net: ethernet: ti: cpsw: fix clean up of vlan mc entries
    for host port (git-fixes).

  - net: ethernet: ti: cpsw: fix error return code in
    cpsw_probe() (git-fixes).

  - net: fec: Fix phy_device lookup for
    phy_reset_after_clk_enable() (git-fixes).

  - net: fec: Fix PHY init after
    phy_reset_after_clk_enable() (git-fixes).

  - net: fec: Fix reference count leak in fec series ops
    (git-fixes).

  - net: gemini: Fix another missing clk_disable_unprepare()
    in probe (git-fixes).

  - net: gemini: Fix missing free_netdev() in error path of
    gemini_ethernet_port_probe() (git-fixes).

  - net: gianfar: Add of_node_put() before goto statement
    (git-fixes).

  - net: hdlc: In hdlc_rcv, check to make sure dev is an
    HDLC device (git-fixes).

  - net: hdlc_raw_eth: Clear the IFF_TX_SKB_SHARING flag
    after calling ether_setup (git-fixes).

  - net: hns3: Remove the left over redundant check &
    assignment (bsc#1154353).

  - net: korina: cast KSEG0 address to pointer in kfree
    (git-fixes).

  - net: korina: fix kfree of rx/tx descriptor array
    (git-fixes).

  - net: lantiq: Wait for the GPHY firmware to be ready
    (git-fixes).

  - net/mlx5: Disable devlink reload for lag devices
    (jsc#SLE-8464).

  - net/mlx5: Disable devlink reload for multi port slave
    device (jsc#SLE-8464).

  - net/mlx5: Disallow RoCE on lag device (jsc#SLE-8464).

  - net/mlx5: Disallow RoCE on multi port slave device
    (jsc#SLE-8464).

  - net/mlx5e: E-switch, Fix rate calculation division
    (jsc#SLE-8464).

  - net/mlx5e: E-switch, Fix rate calculation for overflow
    (jsc#SLE-8464).

  - net/mlx5: Fix PPLM register mapping (jsc#SLE-8464).

  - net: mvneta: fix double free of txq->buf (git-fixes).

  - net: mvneta: make tx buffer array agnostic (git-fixes).

  - net: pasemi: fix error return code in pasemi_mac_open()
    (git-fixes).

  - net: phy: broadcom: Only advertise EEE for supported
    modes (git-fixes).

  - net: qcom/emac: add missed clk_disable_unprepare in
    error path of emac_clks_phase1_init (git-fixes).

  - net: qualcomm: rmnet: Fix incorrect receive packet
    handling during cleanup (git-fixes).

  - net: sched: disable TCQ_F_NOLOCK for pfifo_fast
    (bsc#1183405)

  - netsec: restore phy power state after controller reset
    (bsc#1183757).

  - net: spider_net: Fix the size used in a
    'dma_free_coherent()' call (git-fixes).

  - net: stmmac: Fix incorrect location to set
    real_num_rx|tx_queues (git-fixes).

  - net: stmmac: removed enabling eee in EEE set callback
    (git-fixes).

  - net: stmmac: use netif_tx_start|stop_all_queues()
    function (git-fixes).

  - net: stmmac: Use rtnl_lock/unlock on
    netif_set_real_num_rx_queues() call (git-fixes).

  - net: usb: ax88179_178a: fix missing stop entry in
    driver_info (git-fixes).

  - net: usb: qmi_wwan: allow qmimux add/del with master up
    (git-fixes).

  - net: usb: qmi_wwan: support ZTE P685M modem (git-fixes).

  - net: wan/lmc: unregister device when no matching device
    is found (git-fixes).

  - nfp: flower: fix pre_tun mask id allocation
    (bsc#1154353).

  - nvme: allocate the keep alive request using
    BLK_MQ_REQ_NOWAIT (bsc#1182077).

  - nvme-fabrics: fix kato initialization (bsc#1182591).

  - nvme-fabrics: only reserve a single tag (bsc#1182077).

  - nvme-fc: fix racing controller reset and create
    association (bsc#1183048).

  - nvme-hwmon: Return error code when registration fails
    (bsc#1177326).

  - nvme: merge nvme_keep_alive into nvme_keep_alive_work
    (bsc#1182077).

  - nvme: return an error if nvme_set_queue_count() fails
    (bsc#1180197).

  - nvmet-rdma: Fix list_del corruption on queue
    establishment failure (bsc#1183501).

  - objtool: Fix '.cold' section suffix check for newer
    versions of GCC (bsc#1169514).

  - objtool: Fix error handling for STD/CLD warnings
    (bsc#1169514).

  - objtool: Fix retpoline detection in asm code
    (bsc#1169514).

  - ovl: fix dentry leak in ovl_get_redirect (bsc#1184176).

  - ovl: fix out of date comment and unreachable code
    (bsc#1184176).

  - ovl: fix regression with re-formatted lower squashfs
    (bsc#1184176).

  - ovl: fix unneeded call to ovl_change_flags()
    (bsc#1184176).

  - ovl: fix value of i_ino for lower hardlink corner case
    (bsc#1184176).

  - ovl: initialize error in ovl_copy_xattr (bsc#1184176).

  - ovl: relax WARN_ON() when decoding lower directory file
    handle (bsc#1184176).

  - PCI: Add a REBAR size quirk for Sapphire RX 5600 XT
    Pulse (git-fixes).

  - PCI: Add function 1 DMA alias quirk for Marvell 9215
    SATA controller (git-fixes).

  - PCI: Align checking of syscall user config accessors
    (git-fixes).

  - PCI: Decline to resize resources if boot config must be
    preserved (git-fixes).

  - PCI: Fix pci_register_io_range() memory leak
    (git-fixes).

  - PCI: mediatek: Add missing of_node_put() to fix
    reference leak (git-fixes).

  - PCI: qcom: Use PHY_REFCLK_USE_PAD only for ipq8064
    (git-fixes).

  - PCI: xgene-msi: Fix race in installing chained irq
    handler (git-fixes).

  - pinctrl: rockchip: fix restore error in resume
    (git-fixes).

  - Platform: OLPC: Fix probe error handling (git-fixes).

  - platform/x86: acer-wmi: Add ACER_CAP_KBD_DOCK quirk for
    the Aspire Switch 10E SW3-016 (git-fixes).

  - platform/x86: acer-wmi: Add ACER_CAP_SET_FUNCTION_MODE
    capability flag (git-fixes).

  - platform/x86: acer-wmi: Add new force_caps module
    parameter (git-fixes).

  - platform/x86: acer-wmi: Add support for SW_TABLET_MODE
    on Switch devices (git-fixes).

  - platform/x86: acer-wmi: Cleanup accelerometer device
    handling (git-fixes).

  - platform/x86: acer-wmi: Cleanup ACER_CAP_FOO defines
    (git-fixes).

  - platform/x86: intel-hid: Support Lenovo ThinkPad X1
    Tablet Gen 2 (git-fixes).

  - platform/x86: intel-vbtn: Stop reporting SW_DOCK events
    (git-fixes).

  - platform/x86: thinkpad_acpi: Allow the FnLock LED to
    change state (git-fixes).

  - PM: EM: postpone creating the debugfs dir till
    fs_initcall (git-fixes).

  - PM: runtime: Add pm_runtime_resume_and_get to deal with
    usage counter (bsc#1183366).

  - PM: runtime: Fix ordering in pm_runtime_get_suppliers()
    (git-fixes).

  - PM: runtime: Fix race getting/putting suppliers at probe
    (git-fixes).

  - post.sh: Return an error when module update fails
    (bsc#1047233 bsc#1184388).

  - powerpc/64s: Fix instruction encoding for lis in
    ppc_function_entry() (bsc#1065729).

  - powerpc/book3s64/radix: Remove WARN_ON in
    destroy_context() (bsc#1183692 ltc#191963).

  - powerpc/pmem: Include pmem prototypes (bsc#1113295
    git-fixes).

  - powerpc/pseries/mobility: handle premature return from
    H_JOIN (bsc#1181674 ltc#189159 git-fixes bsc#1183662
    ltc#191922).

  - powerpc/pseries/mobility: use struct for shared state
    (bsc#1181674 ltc#189159 git-fixes bsc#1183662
    ltc#191922).

  - powerpc/pseries/ras: Remove unused variable 'status'
    (bsc#1065729).

  - powerpc/sstep: Check instruction validity against ISA
    version before emulation (bsc#1156395).

  - powerpc/sstep: Fix darn emulation (bsc#1156395).

  - powerpc/sstep: Fix incorrect return from analyze_instr()
    (bsc#1156395).

  - powerpc/sstep: Fix load-store and update emulation
    (bsc#1156395).

  - printk: fix deadlock when kernel panic (bsc#1183018).

  - proc: fix lookup in /proc/net subdirectories after
    setns(2) (git-fixes).

  - pwm: rockchip: rockchip_pwm_probe(): Remove superfluous
    clk_unprepare() (git-fixes).

  - qlcnic: fix error return code in
    qlcnic_83xx_restart_hw() (git-fixes).

  - qxl: Fix uninitialised struct field head.surface_id
    (git-fixes).

  - random: fix the RNDRESEEDCRNG ioctl (git-fixes).

  - RAS/CEC: Correct ce_add_elem()'s returned values
    (bsc#1152489).

  - RDMA/hns: Disable RQ inline by default (jsc#SLE-8449).

  - RDMA/hns: Fix type of sq_signal_bits (jsc#SLE-8449).

  - RDMA/srp: Fix support for unpopulated and unbalanced
    NUMA nodes (bsc#1169709)

  - regulator: bd9571mwv: Fix AVS and DVFS voltage range
    (git-fixes).

  - Revert 'net: bonding: fix error return code of
    bond_neigh_init()' (bsc#1154353).

  - rpadlpar: fix potential drc_name corruption in store
    functions (bsc#1183416 ltc#191079).

  - rpm/check-for-config-changes: add -mrecord-mcount ignore
    Added by 3b15cdc15956 (tracing: move function tracer
    options to Kconfig) upstream.

  - rpm/check-for-config-changes: Also ignore AS_VERSION
    added in 5.12.

  - rpm/check-for-config-changes: comment on the list To
    explain what it actually is.

  - rpm/check-for-config-changes: declare sed args as an
    array So that we can reuse it in both seds. This also
    introduces IGNORED_CONFIGS_RE array which can be easily
    extended.

  - rpm/check-for-config-changes: define ignores more
    strictly * search for whole words, so make wildcards
    explicit * use ' for quoting * prepend CONFIG_
    dynamically, so it need not be in the list

  - rpm/check-for-config-changes: sort the ignores They are
    growing so to make them searchable by humans.

  - rpm/kernel-binary.spec.in: Fix dependency of
    kernel-*-devel package (bsc#1184514) The devel package
    requires the kernel binary package itself for building
    modules externally.

  - rsi: Fix TX EAPOL packet handling against iwlwifi AP
    (git-fixes).

  - rsi: Move card interrupt handling to RX thread
    (git-fixes).

  - rsxx: Return -EFAULT if copy_to_user() fails
    (git-fixes).

  - s390/cio: return -EFAULT if copy_to_user() fails
    (git-fixes).

  - s390/cio: return -EFAULT if copy_to_user() fails
    (git-fixes).

  - s390/crypto: return -EFAULT if copy_to_user() fails
    (git-fixes).

  - s390/dasd: fix hanging IO request during DASD driver
    unbind (git-fixes).

  - s390/qeth: fix memory leak after failed TX Buffer
    allocation (git-fixes).

  - s390/qeth: fix notification for pending buffers during
    teardown (git-fixes).

  - s390/qeth: improve completion of pending TX buffers
    (git-fixes).

  - s390/qeth: schedule TX NAPI on QAOB completion
    (git-fixes).

  - s390/vtime: fix increased steal time accounting
    (bsc#1183859).

  - samples, bpf: Add missing munmap in xdpsock
    (bsc#1155518).

  - scsi: ibmvfc: Fix invalid state machine BUG_ON()
    (bsc#1184647 ltc#191231).

  - scsi: lpfc: Change wording of invalid pci reset log
    message (bsc#1182574).

  - scsi: lpfc: Correct function header comments related to
    ndlp reference counting (bsc#1182574).

  - scsi: lpfc: Fix ADISC handling that never frees nodes
    (bsc#1182574).

  - scsi: lpfc: Fix crash caused by switch reboot
    (bsc#1182574).

  - scsi: lpfc: Fix dropped FLOGI during pt2pt discovery
    recovery (bsc#1182574).

  - scsi: lpfc: Fix FLOGI failure due to accessing a freed
    node (bsc#1182574).

  - scsi: lpfc: Fix incorrect dbde assignment when building
    target abts wqe (bsc#1182574).

  - scsi: lpfc: Fix lpfc_els_retry() possible NULL pointer
    dereference (bsc#1182574).

  - scsi: lpfc: Fix nodeinfo debugfs output (bsc#1182574).

  - scsi: lpfc: Fix NULL pointer dereference in
    lpfc_prep_els_iocb() (bsc#1182574).

  - scsi: lpfc: Fix PLOGI ACC to be transmit after REG_LOGIN
    (bsc#1182574).

  - scsi: lpfc: Fix pt2pt connection does not recover after
    LOGO (bsc#1182574).

  - scsi: lpfc: Fix pt2pt state transition causing rmmod
    hang (bsc#1182574).

  - scsi: lpfc: Fix reftag generation sizing errors
    (bsc#1182574).

  - scsi: lpfc: Fix stale node accesses on stale RRQ request
    (bsc#1182574).

  - scsi: lpfc: Fix status returned in lpfc_els_retry()
    error exit path (bsc#1182574).

  - scsi: lpfc: Fix unnecessary null check in
    lpfc_release_scsi_buf (bsc#1182574).

  - scsi: lpfc: Fix use after free in lpfc_els_free_iocb
    (bsc#1182574).

  - scsi: lpfc: Fix vport indices in
    lpfc_find_vport_by_vpid() (bsc#1182574).

  - scsi: lpfc: Reduce LOG_TRACE_EVENT logging for vports
    (bsc#1182574).

  - scsi: lpfc: Update copyrights for 12.8.0.7 and 12.8.0.8
    changes (bsc#1182574).

  - scsi: lpfc: Update lpfc version to 12.8.0.8
    (bsc#1182574).

  - scsi: target: pscsi: Avoid OOM in pscsi_map_sg()
    (bsc#1183843).

  - scsi: target: pscsi: Clean up after failure in
    pscsi_map_sg() (bsc#1183843).

  - selftests/bpf: Mask bpf_csum_diff() return value to 16
    bits in test_verifier (bsc#1155518).

  - selftests/bpf: No need to drop the packet when there is
    no geneve opt (bsc#1155518).

  - selftests/bpf: Set gopt opt_class to 0 if get tunnel opt
    failed (bsc#1155518).

  - selinux: fix error initialization in
    inode_doinit_with_dentry() (git-fixes).

  - selinux: Fix error return code in sel_ib_pkey_sid_slow()
    (git-fixes).

  - selinux: fix inode_doinit_with_dentry() LABEL_INVALID
    error handling (git-fixes).

  - smb3: add dynamic trace point to trace when credits
    obtained (bsc#1181507).

  - smb3: fix crediting for compounding when only one
    request in flight (bsc#1181507).

  - smb3: Fix out-of-bounds bug in SMB2_negotiate()
    (bsc#1183540).

  - soc/fsl: qbman: fix conflicting alignment attributes
    (git-fixes).

  - software node: Fix node registration (git-fixes).

  - spi: stm32: make spurious and overrun interrupts visible
    (git-fixes).

  - squashfs: fix inode lookup sanity checks (bsc#1183750).

  - squashfs: fix xattr id and id lookup sanity checks
    (bsc#1183750).

  - stop_machine: mark helpers __always_inline (git-fixes).

  - thermal/core: Add NULL pointer check before using
    cooling device stats (git-fixes).

  - udlfb: Fix memory leak in dlfb_usb_probe (git-fixes).

  - Update bug reference for USB-audio fixes (bsc#1182552
    bsc#1183598)

  - USB: cdc-acm: downgrade message to debug (git-fixes).

  - USB: cdc-acm: fix double free on probe failure
    (git-fixes).

  - USB: cdc-acm: fix use-after-free after probe failure
    (git-fixes).

  - USB: cdc-acm: untangle a circular dependency between
    callback and softint (git-fixes).

  - USB: dwc2: Fix HPRT0.PrtSusp bit setting for HiKey 960
    board (git-fixes).

  - USB: dwc2: Prevent core suspend when port connection
    flag is 0 (git-fixes).

  - USB: dwc3: gadget: Fix dep->interval for fullspeed
    interrupt (git-fixes).

  - USB: dwc3: gadget: Fix setting of DEPCFG.bInterval_m1
    (git-fixes).

  - USB: dwc3: qcom: Add missing DWC3 OF node refcount
    decrement (git-fixes).

  - USB: dwc3: qcom: Honor wakeup enabled/disabled state
    (git-fixes).

  - USB: gadget: configfs: Fix KASAN use-after-free
    (git-fixes).

  - USB: gadget: f_uac1: stop playback on function disable
    (git-fixes).

  - USB: gadget: f_uac2: always increase endpoint
    max_packet_size by one audio slot (git-fixes).

  - USB: gadget: udc: amd5536udc_pci fix
    null-ptr-dereference (git-fixes).

  - USB: gadget: u_ether: Fix a configfs return code
    (git-fixes).

  - USBip: Fix incorrect double assignment to udc->ud.tcp_rx
    (git-fixes).

  - USBip: fix stub_dev to check for stream socket
    (git-fixes).

  - USBip: fix stub_dev usbip_sockfd_store() races leading
    to gpf (git-fixes).

  - USBip: fix vhci_hcd attach_store() races leading to gpf
    (git-fixes).

  - USBip: fix vhci_hcd to check for stream socket
    (git-fixes).

  - USBip: fix vudc to check for stream socket (git-fixes).

  - USBip: fix vudc usbip_sockfd_store races leading to gpf
    (git-fixes).

  - USBip: tools: fix build error for multiple definition
    (git-fixes).

  - USBip: vhci_hcd fix shift out-of-bounds in
    vhci_hub_control() (git-fixes).

  - USB: musb: Fix suspend with devices connected for a64
    (git-fixes).

  - USB: quirks: ignore remote wake-up on Fibocom L850-GL
    LTE modem (git-fixes).

  - USB: renesas_usbhs: Clear PIPECFG for re-enabling pipe
    with other EPNUM (git-fixes).

  - USB: replace hardcode maximum usb string length by
    definition (git-fixes).

  - USB: serial: ch341: add new Product ID (git-fixes).

  - USB: serial: cp210x: add ID for Acuity Brands nLight Air
    Adapter (git-fixes).

  - USB: serial: cp210x: add some more GE USB IDs
    (git-fixes).

  - USB: serial: ftdi_sio: fix FTX sub-integer prescaler
    (git-fixes).

  - USB: serial: io_edgeport: fix memory leak in
    edge_startup (git-fixes).

  - USB-storage: Add quirk to defeat Kindle's automatic
    unload (git-fixes).

  - USB: typec: tcpm: Invoke power_supply_changed for
    tcpm-source-psy- (git-fixes).

  - USB: usblp: fix a hang in poll() if disconnected
    (git-fixes).

  - USB: xhci: do not perform Soft Retry for some xHCI hosts
    (git-fixes).

  - USB: xhci: Fix ASMedia ASM1042A and ASM3242 DMA
    addressing (git-fixes).

  - USB: xhci-mtk: fix broken streams issue on 0.96 xHCI
    (git-fixes).

  - use __netdev_notify_peers in ibmvnic (bsc#1183871
    ltc#192139).

  - video: fbdev: acornfb: remove free_unused_pages()
    (bsc#1152489)

  - video: hyperv_fb: Fix a double free in hvfb_probe
    (git-fixes).

  - VMCI: Use set_page_dirty_lock() when unregistering guest
    memory (git-fixes).

  - vt/consolemap: do font sum unsigned (git-fixes).

  - watchdog: mei_wdt: request stop on unregister
    (git-fixes).

  - wireguard: device: do not generate ICMP for non-IP
    packets (git-fixes).

  - wireguard: kconfig: use arm chacha even with no neon
    (git-fixes).

  - wireguard: selftests: test multiple parallel streams
    (git-fixes).

  - wlcore: Fix command execute failure 19 for wl12xx
    (git-fixes).

  - x86/fsgsbase/64: Fix NULL deref in 86_fsgsbase_read_task
    (bsc#1152489).

  - x86: Introduce TS_COMPAT_RESTART to fix
    get_nr_restart_syscall() (bsc#1152489).

  - x86/ioapic: Ignore IRQ2 again (bsc#1152489).

  - x86/mem_encrypt: Correct physical address calculation in
    __set_clr_pte_enc() (bsc#1152489).

  - xen/events: avoid handling the same event on two cpus at
    the same time (git-fixes).

  - xen/events: do not unmask an event channel when an eoi
    is pending (git-fixes).

  - xen/events: fix setting irq affinity (bsc#1184583).

  - xen/events: reset affinity of 2-level event when tearing
    it down (git-fixes).

  - xen/gnttab: handle p2m update errors on a per-slot basis
    (bsc#1183022 XSA-367).

  - xen-netback: respect gnttab_map_refs()'s return value
    (bsc#1183022 XSA-367).

  - xfs: group quota should return EDQUOT when prj quota
    enabled (bsc#1180980).

  - xhci: Fix repeated xhci wake after suspend due to
    uncleared internal wake state (git-fixes).

  - xhci: Improve detection of device initiated wake signal
    (git-fixes).

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184647");
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-rt_debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-rt_debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-rt_debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-rt_debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-rt_debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-rt_debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"cluster-md-kmp-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cluster-md-kmp-rt-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cluster-md-kmp-rt_debug-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cluster-md-kmp-rt_debug-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dlm-kmp-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dlm-kmp-rt-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dlm-kmp-rt_debug-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dlm-kmp-rt_debug-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gfs2-kmp-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gfs2-kmp-rt-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gfs2-kmp-rt_debug-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gfs2-kmp-rt_debug-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt-debugsource-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt-devel-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt-devel-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt-extra-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt-extra-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt_debug-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt_debug-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt_debug-debugsource-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt_debug-devel-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt_debug-devel-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt_debug-extra-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-rt_debug-extra-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kselftests-kmp-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kselftests-kmp-rt-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kselftests-kmp-rt_debug-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kselftests-kmp-rt_debug-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ocfs2-kmp-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ocfs2-kmp-rt-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ocfs2-kmp-rt_debug-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ocfs2-kmp-rt_debug-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"reiserfs-kmp-rt-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"reiserfs-kmp-rt-debuginfo-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"reiserfs-kmp-rt_debug-5.3.18-lp152.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"reiserfs-kmp-rt_debug-debuginfo-5.3.18-lp152.3.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cluster-md-kmp-rt / cluster-md-kmp-rt-debuginfo / dlm-kmp-rt / etc");
}
