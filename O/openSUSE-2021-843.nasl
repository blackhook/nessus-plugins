#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-843.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150315);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/15");

  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-3491");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2021-843)");
  script_summary(english:"Check for the openSUSE-2021-843 patch");

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

  - CVE-2021-33200: Enforcing incorrect limits for pointer
    arithmetic operations by the BPF verifier could be
    abused to perform out-of-bounds reads and writes in
    kernel memory (bsc#1186484).

  - CVE-2021-33034: Fixed a use-after-free when destroying
    an hci_chan. This could lead to writing an arbitrary
    values. (bsc#1186111)

  - CVE-2020-26139: Fixed a denial-of-service when an Access
    Point (AP) forwards EAPOL frames to other clients even
    though the sender has not yet successfully authenticated
    to the AP. (bnc#1186062)

  - CVE-2021-23134: A Use After Free vulnerability in nfc
    sockets allowed local attackers to elevate their
    privileges. (bnc#1186060)

  - CVE-2021-3491: Fixed a potential heap overflow in
    mem_rw(). This vulnerability is related to the
    PROVIDE_BUFFERS operation, which allowed the
    MAX_RW_COUNT limit to be bypassed (bsc#1185642).

  - CVE-2021-32399: Fixed a race condition when removing the
    HCI controller (bnc#1184611).

  - CVE-2020-24586: The 802.11 standard that underpins Wi-Fi
    Protected Access (WPA, WPA2, and WPA3) and Wired
    Equivalent Privacy (WEP) doesn't require that received
    fragments be cleared from memory after (re)connecting to
    a network. Under the right circumstances this can be
    abused to inject arbitrary network packets and/or
    exfiltrate user data (bnc#1185859).

  - CVE-2020-24587: The 802.11 standard that underpins Wi-Fi
    Protected Access (WPA, WPA2, and WPA3) and Wired
    Equivalent Privacy (WEP) doesn't require that all
    fragments of a frame are encrypted under the same key.
    An adversary can abuse this to decrypt selected
    fragments when another device sends fragmented frames
    and the WEP, CCMP, or GCMP encryption key is
    periodically renewed (bnc#1185859 bnc#1185862).

  - CVE-2020-24588: The 802.11 standard that underpins Wi-Fi
    Protected Access (WPA, WPA2, and WPA3) and Wired
    Equivalent Privacy (WEP) doesn't require that the A-MSDU
    flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU
    frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network
    packets. (bnc#1185861)

  - CVE-2020-26147: The WEP, WPA, WPA2, and WPA3
    implementations reassemble fragments, even though some
    of them were sent in plaintext. This vulnerability can
    be abused to inject packets and/or exfiltrate selected
    fragments when another device sends fragmented frames
    and the WEP, CCMP, or GCMP data-confidentiality protocol
    is used (bnc#1185859).

  - CVE-2020-26145: An issue was discovered with Samsung
    Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and
    WPA3 implementations accept second (or subsequent)
    broadcast fragments even when sent in plaintext and
    process them as full unfragmented frames. An adversary
    can abuse this to inject arbitrary network packets
    independent of the network configuration. (bnc#1185860)

  - CVE-2020-26141: An issue was discovered in the ALFA
    driver for AWUS036H, where the Message Integrity Check
    (authenticity) of fragmented TKIP frames was not
    verified. An adversary can abuse this to inject and
    possibly decrypt packets in WPA or WPA2 networks that
    support the TKIP data-confidentiality protocol.
    (bnc#1185987)

The following non-security bugs were fixed :

  - ACPI / hotplug / PCI: Fix reference count leak in
    enable_slot() (git-fixes).

  - ACPI: GTDT: Do not corrupt interrupt mappings on
    watchdow probe failure (git-fixes).

  - ACPI: custom_method: fix a possible memory leak
    (git-fixes).

  - ACPI: custom_method: fix potential use-after-free issue
    (git-fixes).

  - ALSA: bebob/oxfw: fix Kconfig entry for Mackie d.2 Pro
    (git-fixes).

  - ALSA: bebob: enable to deliver MIDI messages for
    multiple ports (git-fixes).

  - ALSA: dice: fix stream format at middle sampling rate
    for Alesis iO 26 (git-fixes).

  - ALSA: dice: fix stream format for TC Electronic Konnekt
    Live at high sampling transfer frequency (git-fixes).

  - ALSA: firewire-lib: fix calculation for size of IR
    context payload (git-fixes).

  - ALSA: firewire-lib: fix check for the size of
    isochronous packet payload (git-fixes).

  - ALSA: hda/conexant: Re-order CX5066 quirk table entries
    (git-fixes).

  - ALSA: hda/realtek: ALC285 Thinkpad jack pin quirk is
    unreachable (git-fixes).

  - ALSA: hda/realtek: Add some CLOVE SSIDs of ALC293
    (git-fixes).

  - ALSA: hda/realtek: Headphone volume is controlled by
    Front mixer (git-fixes).

  - ALSA: hda/realtek: reset eapd coeff to default value for
    alc287 (git-fixes).

  - ALSA: hda: fixup headset for ASUS GU502 laptop
    (git-fixes).

  - ALSA: hda: generic: change the DAC ctl name for LO+SPK
    or LO+HP (git-fixes).

  - ALSA: hdsp: do not disable if not enabled (git-fixes).

  - ALSA: hdspm: do not disable if not enabled (git-fixes).

  - ALSA: intel8x0: Do not update period unless prepared
    (git-fixes).

  - ALSA: line6: Fix racy initialization of LINE6 MIDI
    (git-fixes).

  - ALSA: rme9652: do not disable if not enabled
    (git-fixes).

  - ALSA: usb-audio: Validate MS endpoint descriptors
    (git-fixes).

  - ALSA: usb-audio: fix control-request direction
    (git-fixes).

  - ALSA: usb-audio: scarlett2: Fix device hang with
    ehci-pci (git-fixes).

  - ALSA: usb-audio: scarlett2: Improve driver startup
    messages (git-fixes).

  - ALSA: usb-audio: scarlett2:
    snd_scarlett_gen2_controls_create() can be static
    (git-fixes).

  - ARM64: vdso32: Install vdso32 from vdso_install
    (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Add quirk for the Chuwi Hi8
    tablet (git-fixes).

  - ASoC: Intel: bytcr_rt5640: Enable jack-detect support on
    Asus T100TAF (git-fixes).

  - ASoC: cs35l33: fix an error code in probe() (git-fixes).

  - ASoC: cs42l42: Regmap must use_single_read/write
    (git-fixes).

  - ASoC: rsnd: call rsnd_ssi_master_clk_start() from
    rsnd_ssi_init() (git-fixes).

  - ASoC: rsnd: core: Check convert rate in rsnd_hw_params
    (git-fixes).

  - ASoC: rt286: Generalize support for ALC3263 codec
    (git-fixes).

  - ASoC: rt286: Make RT286_SET_GPIO_* readable and writable
    (git-fixes).

  - Bluetooth: L2CAP: Fix handling LE modes by L2CAP_OPTIONS
    (git-fixes).

  - Bluetooth: SMP: Fail if remote and local public keys are
    identical (git-fixes).

  - Bluetooth: Set CONF_NOT_COMPLETE as l2cap_chan default
    (git-fixes).

  - Bluetooth: check for zapped sk before connecting
    (git-fixes).

  - Bluetooth: initialize skb_queue_head at
    l2cap_chan_create() (git-fixes).

  - Drivers: hv: vmbus: Fix Suspend-to-Idle for Generation-2
    VM (git-fixes).

  - Drivers: hv: vmbus: Increase wait time for VMbus unload
    (bsc#1185725).

  - Drivers: hv: vmbus: Initialize unload_event statically
    (bsc#1185725).

  - Drivers: hv: vmbus: Use after free in __vmbus_open()
    (git-fixes).

  - Input: elants_i2c - do not bind to i2c-hid compatible
    ACPI instantiated devices (git-fixes).

  - Input: silead - add workaround for x86 BIOS-es which
    bring the chip up in a stuck state (git-fixes).

  - KVM: s390: fix guarded storage control register handling
    (bsc#1133021).

  - Move upstreamed media fixes into sorted section

  - NFC: nci: fix memory leak in nci_allocate_device
    (git-fixes).

  - PCI/RCEC: Fix RCiEP device to RCEC association
    (git-fixes).

  - PCI: Allow VPD access for QLogic ISP2722 (git-fixes).

  - PCI: PM: Do not read power state in
    pci_enable_device_flags() (git-fixes).

  - PCI: Release OF node in pci_scan_device()'s error path
    (git-fixes).

  - PCI: endpoint: Fix missing destroy_workqueue()
    (git-fixes).

  - PCI: iproc: Fix return value of
    iproc_msi_irq_domain_alloc() (git-fixes).

  - PCI: thunder: Fix compile testing (git-fixes).

  - PM / devfreq: Use more accurate returned new_freq as
    resume_freq (git-fixes).

  - RDMA/addr: create addr_wq with WQ_MEM_RECLAIM flag
    (bsc#1183346).

  - RDMA/core: create ib_cm with WQ_MEM_RECLAIM flag
    (bsc#1183346).

  - RDMA/hns: Delete redundant abnormal interrupt status
    (git-fixes).

  - RDMA/hns: Delete redundant condition judgment related to
    eq (git-fixes).

  - RDMA/qedr: Fix error return code in qedr_iw_connect()
    (jsc#SLE-8215).

  - RDMA/srpt: Fix error return code in srpt_cm_req_recv()
    (git-fixes).

  - Revert 'arm64: vdso: Fix compilation with clang older
    than 8' (git-fixes).

  - Revert 'gdrom: fix a memory leak bug' (git-fixes).

  - Revert 'i3c master: fix missing destroy_workqueue() on
    error in i3c_master_register' (git-fixes).

  - Revert 'leds: lp5523: fix a missing check of return
    value of lp55xx_read' (git-fixes).

  - Revert 337f13046ff0 ('futex: Allow FUTEX_CLOCK_REALTIME
    with FUTEX_WAIT op') (git-fixes).

  - SUNRPC in case of backlog, hand free slots directly to
    waiting task (bsc#1185428).

  - SUNRPC: More fixes for backlog congestion (bsc#1185428).

  - USB: Add LPM quirk for Lenovo ThinkPad USB-C Dock Gen2
    Ethernet (git-fixes).

  - USB: Add reset-resume quirk for WD19's Realtek Hub
    (git-fixes).

  - USB: serial: pl2303: add support for PL2303HXN
    (bsc#1186320).

  - USB: serial: pl2303: fix line-speed handling on newer
    chips (bsc#1186320).

  - USB: serial: ti_usb_3410_5052: fix TIOCSSERIAL
    permission check (git-fixes).

  - USB: trancevibrator: fix control-request direction
    (git-fixes).

  - amdgpu: avoid incorrect %hu format string (git-fixes).

  - arm64/mm: Fix pfn_valid() for ZONE_DEVICE based memory
    (git-fixes).

  - arm64: Add missing ISB after invalidating TLB in
    __primary_switch (git-fixes).

  - arm64: avoid -Woverride-init warning (git-fixes).

  - arm64: kasan: fix page_alloc tagging with DEBUG_VIRTUAL
    (git-fixes).

  - arm64: kdump: update ppos when reading elfcorehdr
    (git-fixes).

  - arm64: kexec_file: fix memory leakage in create_dtb()
    when fdt_open_into() fails (git-fixes).

  - arm64: link with -z norelro for LLD or aarch64-elf
    (git-fixes).

  - arm64: link with -z norelro regardless of
    CONFIG_RELOCATABLE (git-fixes).

  - arm64: ptrace: Fix seccomp of traced syscall -1
    (NO_SYSCALL) (git-fixes).

  - arm64: ptrace: Use NO_SYSCALL instead of -1 in
    syscall_trace_enter() (git-fixes).

  - arm64: vdso32: make vdso32 install conditional
    (git-fixes).

  - arm: mm: use __pfn_to_section() to get mem_section
    (git-fixes).

  - ata: ahci: Disable SXS for Hisilicon Kunpeng920
    (git-fixes).

  - blk-iocost: ioc_pd_free() shouldn't assume irq disabled
    (git-fixes).

  - blk-mq: Swap two calls in blk_mq_exit_queue()
    (git-fixes).

  - block/genhd: use atomic_t for disk_event->block
    (bsc#1185497).

  - block: Fix three kernel-doc warnings (git-fixes).

  - block: fix get_max_io_size() (git-fixes).

  - bnxt_en: Fix RX consumer index logic in the error path
    (git-fixes).

  - bnxt_en: fix ternary sign extension bug in
    bnxt_show_temp() (git-fixes).

  - bpf: Fix leakage of uninitialized bpf stack under
    speculation (bsc#1155518).

  - bpf: Fix masking negation logic upon negative dst
    register (bsc#1155518).

  - btrfs: fix race between transaction aborts and fsyncs
    leading to use-after-free (bsc#1186441).

  - btrfs: fix race when picking most recent mod log
    operation for an old root (bsc#1186439).

  - cdc-wdm: untangle a circular dependency between callback
    and softint (git-fixes).

  - cdrom: gdrom: deallocate struct gdrom_unit fields in
    remove_gdrom (git-fixes).

  - cdrom: gdrom: initialize global variable at init time
    (git-fixes).

  - ceph: do not clobber i_snap_caps on non-I_NEW inode
    (bsc#1186501).

  - ceph: fix inode leak on getattr error in __fh_to_dentry
    (bsc#1186501).

  - ceph: fix up error handling with snapdirs (bsc#1186501).

  - ceph: only check pool permissions for regular files
    (bsc#1186501).

  - cfg80211: scan: drop entry from hidden_list on overflow
    (git-fixes).

  - clk: socfpga: arria10: Fix memory leak of socfpga_clk on
    error return (git-fixes).

  - cpufreq: intel_pstate: Add Icelake servers support in
    no-HWP mode (bsc#1185758).

  - crypto: api - check for ERR pointers in
    crypto_destroy_tfm() (git-fixes).

  - crypto: mips/poly1305 - enable for all MIPS processors
    (git-fixes).

  - crypto: qat - ADF_STATUS_PF_RUNNING should be set after
    adf_dev_init (git-fixes).

  - crypto: qat - Fix a double free in adf_create_ring
    (git-fixes).

  - crypto: qat - do not release uninitialized resources
    (git-fixes).

  - crypto: qat - fix error path in adf_isr_resource_alloc()
    (git-fixes).

  - crypto: qat - fix unmap invalid dma address (git-fixes).

  - crypto: stm32/cryp - Fix PM reference leak on
    stm32-cryp.c (git-fixes).

  - crypto: stm32/hash - Fix PM reference leak on
    stm32-hash.c (git-fixes).

  - cxgb4: Fix unintentional sign extension issues
    (git-fixes).

  - dm: avoid filesystem lookup in dm_get_dev_t()
    (git-fixes).

  - dmaengine: dw-edma: Fix crash on loading/unloading
    driver (git-fixes).

  - docs: kernel-parameters: Add gpio_mockup_named_lines
    (git-fixes).

  - docs: kernel-parameters: Move gpio-mockup for alphabetic
    order (git-fixes).

  - drivers: hv: Fix whitespace errors (bsc#1185725).

  - drm/amd/display: Fix UBSAN warning for not a valid value
    for type '_Bool' (git-fixes).

  - drm/amd/display: Fix two cursor duplication when using
    overlay (git-fixes).

  - drm/amd/display: Force vsync flip when reconfiguring
    MPCC (git-fixes).

  - drm/amd/display: Reject non-zero src_y and src_x for
    video planes (git-fixes).

  - drm/amd/display: fix dml prefetch validation
    (git-fixes).

  - drm/amd/display: fixed divide by zero kernel crash
    during dsc enablement (git-fixes).

  - drm/amdgpu : Fix asic reset regression issue introduce
    by 8f211fe8ac7c4f (git-fixes).

  - drm/amdgpu: disable 3DCGCG on picasso/raven1 to avoid
    compute hang (git-fixes).

  - drm/amdgpu: fix NULL pointer dereference (git-fixes).

  - drm/amdgpu: mask the xgmi number of hops reported from
    psp to kfd (git-fixes).

  - drm/amdkfd: Fix cat debugfs hang_hws file causes system
    crash bug (git-fixes).

  - drm/i915: Avoid div-by-zero on gen2 (git-fixes).

  - drm/meson: fix shutdown crash when component not probed
    (git-fixes).

  - drm/msm/mdp5: Configure PP_SYNC_HEIGHT to double the
    vtotal (git-fixes).

  - drm/msm/mdp5: Do not multiply vclk line count by 100
    (git-fixes).

  - drm/radeon/dpm: Disable sclk switching on Oland when two
    4K 60Hz monitors are connected (git-fixes).

  - drm/radeon: Avoid power table parsing memory leaks
    (git-fixes).

  - drm/radeon: Fix off-by-one power_state index heap
    overwrite (git-fixes).

  - drm/vkms: fix misuse of WARN_ON (git-fixes).

  - drm: Added orientation quirk for OneGX1 Pro (git-fixes).

  - ethernet:enic: Fix a use after free bug in
    enic_hard_start_xmit (git-fixes).

  - extcon: arizona: Fix some issues when HPDET IRQ fires
    after the jack has been unplugged (git-fixes).

  - extcon: arizona: Fix various races on driver unbind
    (git-fixes).

  - fbdev: zero-fill colormap in fbcmap.c (git-fixes).

  - firmware: arm_scpi: Prevent the ternary sign expansion
    bug (git-fixes).

  - fs/epoll: restore waking from ep_done_scan()
    (bsc#1183868).

  - ftrace: Handle commands when closing set_ftrace_filter
    file (git-fixes).

  - futex: Change utime parameter to be 'const ... *'
    (git-fixes).

  - futex: Do not apply time namespace adjustment on
    FUTEX_LOCK_PI (bsc#1164648).

  - futex: Get rid of the val2 conditional dance
    (git-fixes).

  - futex: Make syscall entry points less convoluted
    (git-fixes).

  - genirq/irqdomain: Do not try to free an interrupt that
    has no (git-fixes)

  - genirq: Disable interrupts for force threaded handlers
    (git-fixes)

  - genirq: Reduce irqdebug cacheline bouncing (bsc#1185703
    ltc#192641).

  - gpio: xilinx: Correct kernel doc for xgpio_probe()
    (git-fixes).

  - gpiolib: acpi: Add quirk to ignore EC wakeups on Dell
    Venue 10 Pro 5055 (git-fixes).

  - hrtimer: Update softirq_expires_next correctly after
    (git-fixes)

  - hwmon: (occ) Fix poll rate limiting (git-fixes).

  - i2c: Add I2C_AQ_NO_REP_START adapter quirk (git-fixes).

  - i2c: bail out early when RDWR parameters are wrong
    (git-fixes).

  - i2c: i801: Do not generate an interrupt on bus reset
    (git-fixes).

  - i2c: s3c2410: fix possible NULL pointer deref on read
    message after write (git-fixes).

  - i2c: sh_mobile: Use new clock calculation formulas for
    RZ/G2E (git-fixes).

  - i40e: Fix PHY type identifiers for 2.5G and 5G adapters
    (git-fixes).

  - i40e: Fix use-after-free in i40e_client_subtask()
    (git-fixes).

  - i40e: fix broken XDP support (git-fixes).

  - i40e: fix the restart auto-negotiation after FEC
    modified (git-fixes).

  - ibmvfc: Avoid move login if fast fail is enabled
    (bsc#1185938 ltc#192043).

  - ibmvfc: Handle move login failure (bsc#1185938
    ltc#192043).

  - ibmvfc: Reinit target retries (bsc#1185938 ltc#192043).

  - ibmvnic: remove default label from to_string switch
    (bsc#1152457 ltc#174432 git-fixes).

  - ics932s401: fix broken handling of errors when word
    reading fails (git-fixes).

  - iio: adc: ad7124: Fix missbalanced regulator enable /
    disable on error (git-fixes).

  - iio: adc: ad7124: Fix potential overflow due to non
    sequential channel numbers (git-fixes).

  - iio: adc: ad7768-1: Fix too small buffer passed to
    iio_push_to_buffers_with_timestamp() (git-fixes).

  - iio: adc: ad7793: Add missing error code in
    ad7793_setup() (git-fixes).

  - iio: gyro: fxas21002c: balance runtime power in error
    path (git-fixes).

  - iio: gyro: mpu3050: Fix reported temperature value
    (git-fixes).

  - iio: proximity: pulsedlight: Fix rumtime PM imbalance on
    error (git-fixes).

  - iio: tsl2583: Fix division by a zero lux_val
    (git-fixes).

  - intel_th: Consistency and off-by-one fix (git-fixes).

  - iommu/amd: Add support for map/unmap_resource
    (jsc#ECO-3482).

  - ipc/mqueue, msg, sem: Avoid relying on a stack reference
    past its expiry (bsc#1185988).

  - ipmi/watchdog: Stop watchdog timer when the current
    action is 'none' (bsc#1184855).

  - kernel-docs.spec.in: Build using an utf-8 locale. Sphinx
    cannot handle UTF-8 input in non-UTF-8 locale.

  - leds: lp5523: check return value of lp5xx_read and jump
    to cleanup code (git-fixes).

  - lpfc: Decouple port_template and vport_template
    (bsc#185032).

  - mac80211: clear the beacon's CRC after channel switch
    (git-fixes).

  - md-cluster: fix use-after-free issue when removing rdev
    (bsc#1184082).

  - md/raid1: properly indicate failure when ending a failed
    write request (bsc#1185680).

  - md: do not flush workqueue unconditionally in md_open
    (bsc#1184081).

  - md: factor out a mddev_find_locked helper from
    mddev_find (bsc#1184081).

  - md: md_open returns -EBUSY when entering racing area
    (bsc#1184081).

  - md: split mddev_find (bsc#1184081).

  - media: adv7604: fix possible use-after-free in
    adv76xx_remove() (git-fixes).

  - media: drivers: media: pci: sta2x11: fix Kconfig
    dependency on GPIOLIB (git-fixes).

  - media: dvb-usb: fix memory leak in dvb_usb_adapter_init
    (git-fixes).

  - media: em28xx: fix memory leak (git-fixes).

  - media: gspca/sq905.c: fix uninitialized variable
    (git-fixes).

  - media: i2c: adv7511-v4l2: fix possible use-after-free in
    adv7511_remove() (git-fixes).

  - media: i2c: adv7842: fix possible use-after-free in
    adv7842_remove() (git-fixes).

  - media: i2c: tda1997: Fix possible use-after-free in
    tda1997x_remove() (git-fixes).

  - media: imx: capture: Return -EPIPE from
    __capture_legacy_try_fmt() (git-fixes).

  - media: ite-cir: check for receive overflow (git-fixes).

  - media: media/saa7164: fix saa7164_encoder_register()
    memory leak bugs (git-fixes).

  - media: platform: sti: Fix runtime PM imbalance in
    regs_show (git-fixes).

  - media: tc358743: fix possible use-after-free in
    tc358743_remove() (git-fixes).

  - mfd: arizona: Fix rumtime PM imbalance on error
    (git-fixes).

  - misc/uss720: fix memory leak in uss720_probe
    (git-fixes).

  - mlxsw: spectrum_mr: Update egress RIF list before
    route's action (git-fixes).

  - mmc: block: Update ext_csd.cache_ctrl if it was written
    (git-fixes).

  - mmc: core: Do a power cycle when the CMD11 fails
    (git-fixes).

  - mmc: core: Set read only for SD cards with permanent
    write protect bit (git-fixes).

  - mmc: sdhci-pci-gli: increase 1.8V regulator wait
    (git-fixes).

  - mmc: sdhci-pci: Add PCI IDs for Intel LKF (git-fixes).

  - mmc: sdhci-pci: Fix initialization of some SD cards for
    Intel BYT-based controllers (git-fixes).

  - mmc: sdhci: Check for reset prior to DMA address unmap
    (git-fixes).

  - net, xdp: Update pkt_type if generic XDP changes unicast
    MAC (git-fixes).

  - net: enetc: fix link error again (git-fixes).

  - net: hns3: Fix for geneve tx checksum bug (git-fixes).

  - net: hns3: add check for HNS3_NIC_STATE_INITED in
    hns3_reset_notify_up_enet() (git-fixes).

  - net: hns3: clear unnecessary reset request in
    hclge_reset_rebuild (git-fixes).

  - net: hns3: disable phy loopback setting in
    hclge_mac_start_phy (git-fixes).

  - net: hns3: fix for vxlan gpe tx checksum bug
    (git-fixes).

  - net: hns3: fix incorrect configuration for
    igu_egu_hw_err (git-fixes).

  - net: hns3: initialize the message content in
    hclge_get_link_mode() (git-fixes).

  - net: hns3: use netif_tx_disable to stop the transmit
    queue (git-fixes).

  - net: thunderx: Fix unintentional sign extension issue
    (git-fixes).

  - net: usb: fix memory leak in smsc75xx_bind (git-fixes).

  - netdevice: Add missing IFF_PHONY_HEADROOM
    self-definition (git-fixes).

  - netfilter: conntrack: add new sysctl to disable RST
    check (bsc#1183947 bsc#1185950).

  - netfilter: conntrack: avoid misleading 'invalid' in log
    message (bsc#1183947 bsc#1185950).

  - netfilter: conntrack: improve RST handling when tuple is
    re-used (bsc#1183947 bsc#1185950).

  - nvme-core: add cancel tagset helpers (bsc#1183976).

  - nvme-fabrics: decode host pathing error for connect
    (bsc#1179827).

  - nvme-fc: check sgl supported by target (bsc#1179827).

  - nvme-fc: clear q_live at beginning of association
    teardown (bsc#1186479).

  - nvme-fc: return NVME_SC_HOST_ABORTED_CMD when a command
    has been aborted (bsc#1184259).

  - nvme-fc: set NVME_REQ_CANCELLED in
    nvme_fc_terminate_exchange() (bsc#1184259).

  - nvme-fc: short-circuit reconnect retries (bsc#1179827).

  - nvme-multipath: fix double initialization of ANA state
    (bsc#1178612, bsc#1184259).

  - nvme-pci: Remove tag from process cq (git-fixes).

  - nvme-pci: Remove two-pass completions (git-fixes).

  - nvme-pci: Simplify nvme_poll_irqdisable (git-fixes).

  - nvme-pci: align io queue count with allocted nvme_queue
    in (git-fixes).

  - nvme-pci: avoid race between nvme_reap_pending_cqes()
    and nvme_poll() (git-fixes).

  - nvme-pci: dma read memory barrier for completions
    (git-fixes).

  - nvme-pci: fix 'slimmer CQ head update' (git-fixes).

  - nvme-pci: make sure write/poll_queues less or equal then
    cpu (git-fixes).

  - nvme-pci: remove last_sq_tail (git-fixes).

  - nvme-pci: remove volatile cqes (git-fixes).

  - nvme-pci: slimmer CQ head update (git-fixes).

  - nvme-pci: use simple suspend when a HMB is enabled
    (git-fixes).

  - nvme-tcp: Fix possible race of io_work and direct send
    (git-fixes).

  - nvme-tcp: Fix warning with CONFIG_DEBUG_PREEMPT
    (git-fixes).

  - nvme-tcp: add clean action for failed reconnection
    (bsc#1183976).

  - nvme-tcp: fix kconfig dependency warning when !CRYPTO
    (git-fixes).

  - nvme-tcp: fix misuse of __smp_processor_id with
    preemption (git-fixes).

  - nvme-tcp: fix possible hang waiting for icresp response
    (bsc#1179519).

  - nvme-tcp: use cancel tagset helper for tear down
    (bsc#1183976).

  - nvme: Fix NULL dereference for pci nvme controllers
    (bsc#1182378).

  - nvme: add NVME_REQ_CANCELLED flag in
    nvme_cancel_request() (bsc#1184259).

  - nvme: define constants for identification values
    (git-fixes).

  - nvme: do not intialize hwmon for discovery controllers
    (bsc#1184259).

  - nvme: do not intialize hwmon for discovery controllers
    (git-fixes).

  - nvme: document nvme controller states (git-fixes).

  - nvme: explicitly update mpath disk capacity on
    revalidation (git-fixes).

  - nvme: expose reconnect_delay and ctrl_loss_tmo via sysfs
    (bsc#1182378).

  - nvme: fix controller instance leak (git-fixes).

  - nvme: fix deadlock in disconnect during scan_work and/or
    ana_work (git-fixes).

  - nvme: fix possible deadlock when I/O is blocked
    (git-fixes).

  - nvme: remove superfluous else in
    nvme_ctrl_loss_tmo_store (bsc#1182378).

  - nvme: retrigger ANA log update if group descriptor isn't
    found (git-fixes)

  - nvme: simplify error logic in nvme_validate_ns()
    (bsc#1184259).

  - nvmet: fix a memory leak (git-fixes).

  - nvmet: seset ns->file when open fails (bsc#1183873).

  - nvmet: use new ana_log_size instead the old one
    (bsc#1184259).

  - nxp-i2c: restore includes for kABI (bsc#1185589).

  - nxp-nci: add NXP1002 id (bsc#1185589).

  - phy: phy-twl4030-usb: Fix possible use-after-free in
    twl4030_usb_remove() (git-fixes).

  - pinctrl: ingenic: Improve unreachable code generation
    (git-fixes).

  - pinctrl: samsung: use 'int' for register masks in Exynos
    (git-fixes).

  - platform/mellanox: mlxbf-tmfifo: Fix a memory barrier
    issue (git-fixes).

  - platform/x86: intel_pmc_core: Do not use global pmcdev
    in quirks (git-fixes).

  - platform/x86: thinkpad_acpi: Correct thermal sensor
    allocation (git-fixes).

  - posix-timers: Preserve return value in clock_adjtime32()
    (git-fixes)

  - power: supply: Use IRQF_ONESHOT (git-fixes).

  - power: supply: generic-adc-battery: fix possible
    use-after-free in gab_remove() (git-fixes).

  - power: supply: s3c_adc_battery: fix possible
    use-after-free in s3c_adc_bat_remove() (git-fixes).

  - powerpc/64s: Fix crashes when toggling entry flush
    barrier (bsc#1177666 git-fixes).

  - powerpc/64s: Fix crashes when toggling stf barrier
    (bsc#1087082 git-fixes).

  - qtnfmac: Fix possible buffer overflow in
    qtnf_event_handle_external_auth (git-fixes).

  - rtc: pcf2127: handle timestamp interrupts (bsc#1185495).

  - s390/dasd: fix hanging DASD driver unbind (bsc#1183932
    LTC#192153).

  - s390/entry: save the caller of psw_idle (bsc#1185677).

  - s390/kdump: fix out-of-memory with PCI (bsc#1182257
    LTC#191375).

  - sched/eas: Do not update misfit status if the task is
    pinned (git-fixes)

  - sched/fair: Avoid stale CPU util_est value for schedutil
    in (git-fixes)

  - sched/fair: Fix unfairness caused by missing load decay
    (git-fixes)

  - scripts/git_sort/git_sort.py: add bpf git repo

  - scsi: core: Run queue in case of I/O resource contention
    failure (bsc#1186416).

  - scsi: fnic: Kill 'exclude_id' argument to
    fnic_cleanup_io() (bsc#1179851).

  - scsi: libfc: Avoid invoking response handler twice if ep
    is already completed (bsc#1186573).

  - scsi: lpfc: Add a option to enable interlocked ABTS
    before job completion (bsc#1186451).

  - scsi: lpfc: Add ndlp kref accounting for resume RPI path
    (bsc#1186451).

  - scsi: lpfc: Fix 'Unexpected timeout' error in direct
    attach topology (bsc#1186451).

  - scsi: lpfc: Fix Node recovery when driver is handling
    simultaneous PLOGIs (bsc#1186451).

  - scsi: lpfc: Fix bad memory access during VPD DUMP
    mailbox command (bsc#1186451).

  - scsi: lpfc: Fix crash when lpfc_sli4_hba_setup() fails
    to initialize the SGLs (bsc#1186451).

  - scsi: lpfc: Fix node handling for Fabric Controller and
    Domain Controller (bsc#1186451).

  - scsi: lpfc: Fix non-optimized ERSP handling
    (bsc#1186451).

  - scsi: lpfc: Fix unreleased RPIs when NPIV ports are
    created (bsc#1186451).

  - scsi: lpfc: Ignore GID-FT response that may be received
    after a link flip (bsc#1186451).

  - scsi: lpfc: Reregister FPIN types if ELS_RDF is received
    from fabric controller (bsc#1186451).

  - scsi: lpfc: Update lpfc version to 12.8.0.10
    (bsc#1186451).

  - sctp: delay auto_asconf init until binding the first
    addr (<cover.1620748346.git.mkubecek@suse.cz>).

  - serial: core: fix suspicious security_locked_down() call
    (git-fixes).

  - serial: core: return early on unsupported ioctls
    (git-fixes).

  - serial: sh-sci: Fix off-by-one error in FIFO threshold
    register setting (git-fixes).

  - serial: stm32: fix incorrect characters on console
    (git-fixes).

  - serial: stm32: fix tx_empty condition (git-fixes).

  - serial: tegra: Fix a mask operation that is always true
    (git-fixes).

  - smc: disallow TCP_ULP in smc_setsockopt() (git-fixes).

  - spi: ath79: always call chipselect function (git-fixes).

  - spi: ath79: remove spi-master setup and cleanup
    assignment (git-fixes).

  - spi: dln2: Fix reference leak to master (git-fixes).

  - spi: omap-100k: Fix reference leak to master
    (git-fixes).

  - spi: qup: fix PM reference leak in spi_qup_remove()
    (git-fixes).

  - spi: spi-fsl-dspi: Fix a resource leak in an error
    handling path (git-fixes).

  - staging: emxx_udc: fix loop in _nbu2ss_nuke()
    (git-fixes).

  - staging: iio: cdc: ad7746: avoid overwrite of
    num_channels (git-fixes).

  - tcp: fix to update snd_wl1 in bulk receiver fast path
    (<cover.1620748346.git.mkubecek@suse.cz>).

  - thermal/drivers/ti-soc-thermal/bandgap Remove unused
    variable 'val' (git-fixes).

  - thunderbolt: dma_port: Fix NVM read buffer bounds and
    offset issue (git-fixes).

  - tracing: Map all PIDs to command lines (git-fixes).

  - tty: amiserial: fix TIOCSSERIAL permission check
    (git-fixes).

  - tty: fix memory leak in vc_deallocate (git-fixes).

  - tty: moxa: fix TIOCSSERIAL jiffies conversions
    (git-fixes).

  - tty: moxa: fix TIOCSSERIAL permission check (git-fixes).

  - uio: uio_hv_generic: use devm_kzalloc() for private data
    alloc (git-fixes).

  - uio_hv_generic: Fix a memory leak in error handling
    paths (git-fixes).

  - uio_hv_generic: Fix another memory leak in error
    handling paths (git-fixes).

  - uio_hv_generic: add missed sysfs_remove_bin_file
    (git-fixes).

  - usb: core: hub: Fix PM reference leak in
    usb_port_resume() (git-fixes).

  - usb: core: hub: fix race condition about TRSMRCY of
    resume (git-fixes).

  - usb: dwc2: Fix gadget DMA unmap direction (git-fixes).

  - usb: dwc3: gadget: Enable suspend events (git-fixes).

  - usb: dwc3: gadget: Return success always for kick
    transfer in ep queue (git-fixes).

  - usb: dwc3: omap: improve extcon initialization
    (git-fixes).

  - usb: dwc3: pci: Enable usb2-gadget-lpm-disable for Intel
    Merrifield (git-fixes).

  - usb: fotg210-hcd: Fix an error message (git-fixes).

  - usb: gadget/function/f_fs string table fix for multiple
    languages (git-fixes).

  - usb: gadget: dummy_hcd: fix gpf in gadget_setup
    (git-fixes).

  - usb: gadget: f_uac1: validate input parameters
    (git-fixes).

  - usb: gadget: f_uac2: validate input parameters
    (git-fixes).

  - usb: gadget: udc: renesas_usb3: Fix a race in
    usb3_start_pipen() (git-fixes).

  - usb: gadget: uvc: add bInterval checking for HS mode
    (git-fixes).

  - usb: musb: fix PM reference leak in musb_irq_work()
    (git-fixes).

  - usb: sl811-hcd: improve misleading indentation
    (git-fixes).

  - usb: webcam: Invalid size of Processing Unit Descriptor
    (git-fixes).

  - usb: xhci: Fix port minor revision (git-fixes).

  - usb: xhci: Increase timeout for HC halt (git-fixes).

  - vgacon: Record video mode changes with VT_RESIZEX
    (git-fixes).

  - video: hyperv_fb: Add ratelimit on error message
    (bsc#1185725).

  - vrf: fix a comment about loopback device (git-fixes).

  - watchdog/softlockup: Remove obsolete check of last
    reported task (bsc#1185982).

  - watchdog/softlockup: report the overall time of
    softlockups (bsc#1185982).

  - watchdog: explicitly update timestamp when reporting
    softlockup (bsc#1185982).

  - watchdog: rename __touch_watchdog() to a better
    descriptive name (bsc#1185982).

  - whitespace cleanup

  - wl3501_cs: Fix out-of-bounds warnings in
    wl3501_mgmt_join (git-fixes).

  - wl3501_cs: Fix out-of-bounds warnings in wl3501_send_pkt
    (git-fixes).

  - workqueue: Minor follow-ups to the rescuer destruction
    change (bsc#1185911).

  - workqueue: more destroy_workqueue() fixes (bsc#1185911).

  - x86/cpu: Initialize MSR_TSC_AUX if RDTSCP *or* RDPID is
    supported (bsc#1152489).

  - xhci: Do not use GFP_KERNEL in (potentially) atomic
    context (git-fixes).

  - xhci: check control context is valid before
    dereferencing it (git-fixes).

  - xhci: fix potential array out of bounds with several
    interrupters (git-fixes).

  - xsk: Respect device's headroom and tailroom on generic
    xmit path (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1186573"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3491");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.78.1.lp152.8.34.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.78.1.lp152.8.34.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.78.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.78.1") ) flag++;

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
