#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2675.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(132032);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/24");

  script_cve_id("CVE-2019-14895", "CVE-2019-14901", "CVE-2019-15211", "CVE-2019-15213", "CVE-2019-15916", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18809", "CVE-2019-19046", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19078", "CVE-2019-19080", "CVE-2019-19081", "CVE-2019-19082", "CVE-2019-19083", "CVE-2019-19227", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19534", "CVE-2019-19536", "CVE-2019-19543");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-2675)");
  script_summary(english:"Check for the openSUSE-2019-2675 patch");

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

  - CVE-2019-15211: There was a use-after-free caused by a
    malicious USB device in
    drivers/media/v4l2-core/v4l2-dev.c (bnc#1146519).

  - CVE-2019-15213: There was a use-after-free caused by a
    malicious USB device in the
    drivers/media/usb/dvb-usb/dvb-usb-init.c driver
    (bnc#1146544).

  - CVE-2019-19531: There was a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/usb/misc/yurex.c driver, aka CID-fc05481b2fca
    (bnc#1158427 1158445).

  - CVE-2019-19543: There is a use-after-free in
    serial_ir_init_module() in drivers/media/rc/serial_ir.c
    (bnc#1158427).

  - CVE-2019-19525: There is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/net/ieee802154/atusb.c driver, aka
    CID-7fd25e6fc035 (bnc#1158417).

  - CVE-2019-19530: There is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/usb/class/cdc-acm.c driver, aka CID-c52873e5a1ef
    (bnc#1158410).

  - CVE-2019-19536: There is an info-leak bug that can be
    caused by a malicious USB device in the
    drivers/net/can/usb/peak_usb/pcan_usb_pro.c driver, aka
    CID-ead16e53c2f0 (bnc#1158394).

  - CVE-2019-19524: There is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9
    (bnc#1158413).

  - CVE-2019-19528: There is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/usb/misc/iowarrior.c driver, aka
    CID-edc4746f253d (bnc#1158407).

  - CVE-2019-19534: There is an info-leak bug that can be
    caused by a malicious USB device in the
    drivers/net/can/usb/peak_usb/pcan_usb_core.c driver, aka
    CID-f7a1337f0d29 (bnc#1158398).

  - CVE-2019-19529: There is a use-after-free bug that can
    be caused by a malicious USB device in the
    drivers/net/can/usb/mcba_usb.c driver, aka
    CID-4d6636498c41 (bnc#1158381).

  - CVE-2019-14901: A heap overflow flaw was found in the
    Marvell WiFi chip driver. The vulnerability allowed a
    remote attacker to cause a system crash, resulting in a
    denial of service, or execute arbitrary code. The
    highest threat with this vulnerability is with the
    availability of the system. If code execution occurs,
    the code will run with the permissions of root. This
    will affect both confidentiality and integrity of files
    on the system (bnc#1157042).

  - CVE-2019-14895: A heap-based buffer overflow was
    discovered in the Marvell WiFi chip driver. The flaw
    could occur when the station attempts a connection
    negotiation during the handling of the remote devices
    country settings. This could allowed the remote device
    to cause a denial of service (system crash) or possibly
    execute arbitrary code (bnc#1157158).

  - CVE-2019-18660: The Linux kernel on powerpc allowed
    Information Exposure because the Spectre-RSB mitigation
    is not in place for all applicable CPUs, aka
    CID-39e72bf96f58. This is related to
    arch/powerpc/kernel/entry_64.S and
    arch/powerpc/kernel/security.c (bnc#1157038).

  - CVE-2019-18683: An issue was discovered in
    drivers/media/platform/vivid, which was exploitable for
    privilege escalation on some Linux distributions where
    local users have /dev/video0 access, but only if the
    driver happens to be loaded. There are multiple race
    conditions during streaming stopping in this driver
    (part of the V4L2 subsystem). These issues are caused by
    wrong mutex locking in vivid_stop_generating_vid_cap(),
    vivid_stop_generating_vid_out(),
    sdr_cap_stop_streaming(), and the corresponding
    kthreads. At least one of these race conditions leads to
    a use-after-free (bnc#1155897).

  - CVE-2019-18809: A memory leak in the
    af9005_identify_state() function in
    drivers/media/usb/dvb-usb/af9005.c allowed attackers to
    cause a denial of service (memory consumption), aka
    CID-2289adbfa559 (bnc#1156258).

  - CVE-2019-19046: A memory leak in the
    __ipmi_bmc_register() function in
    drivers/char/ipmi/ipmi_msghandler.c was fixed
    (bnc#1157304).

  - CVE-2019-19078: A memory leak in the
    ath10k_usb_hif_tx_sg() function in
    drivers/net/wireless/ath/ath10k/usb.c allowed attackers
    to cause a denial of service (memory consumption) by
    triggering usb_submit_urb() failures, aka
    CID-b8d17e7d93d2 (bnc#1157032).

  - CVE-2019-19062: A memory leak in the crypto_report()
    function in crypto/crypto_user_base.c allowed attackers
    to cause a denial of service (memory consumption) by
    triggering crypto_report_alg() failures, aka
    CID-ffdde5932042 (bnc#1157333).

  - CVE-2019-19057: Two memory leaks in the
    mwifiex_pcie_init_evt_ring() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering mwifiex_map_pci_memory()
    failures, aka CID-d10dcb615c8e (bnc#1157193).

  - CVE-2019-19056: A memory leak in the
    mwifiex_pcie_alloc_cmdrsp_buf() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering mwifiex_map_pci_memory()
    failures, aka CID-db8fd2cde932 (bnc#1157197).

  - CVE-2019-19068: A memory leak in the
    rtl8xxxu_submit_int_urb() function in
    drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c
    allowed attackers to cause a denial of service (memory
    consumption) by triggering usb_submit_urb() failures,
    aka CID-a2cdd07488e6 (bnc#1157307).

  - CVE-2019-19063: Two memory leaks in the rtl_usb_probe()
    function in drivers/net/wireless/realtek/rtlwifi/usb.c
    allowed attackers to cause a denial of service (memory
    consumption), aka CID-3f9361695113 (bnc#1157298).

  - CVE-2019-19227: In the AppleTalk subsystem there was a
    potential NULL pointer dereference because
    register_snap_client may return NULL. This will lead to
    denial of service in net/appletalk/aarp.c and
    net/appletalk/ddp.c, as demonstrated by
    unregister_snap_client, aka CID-9804501fa122
    (bnc#1157678).

  - CVE-2019-19081: A memory leak in the
    nfp_flower_spawn_vnic_reprs() function in
    drivers/net/ethernet/netronome/nfp/flower/main.c allowed
    attackers to cause a denial of service (memory
    consumption), aka CID-8ce39eb5a67a (bnc#1157045).

  - CVE-2019-19080: Four memory leaks in the
    nfp_flower_spawn_phy_reprs() function in
    drivers/net/ethernet/netronome/nfp/flower/main.c allowed
    attackers to cause a denial of service (memory
    consumption), aka CID-8572cea1461a (bnc#1157044).

  - CVE-2019-19065: A memory leak in the sdma_init()
    function in drivers/infiniband/hw/hfi1/sdma.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering rhashtable_init() failures,
    aka CID-34b3be18a04e (bnc#1157191).

  - CVE-2019-19077: A memory leak in the
    bnxt_re_create_srq() function in
    drivers/infiniband/hw/bnxt_re/ib_verbs.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering copy to udata failures, aka
    CID-4a9d46a9fe14 (bnc#1157171).

  - CVE-2019-19052: A memory leak in the gs_can_open()
    function in drivers/net/can/usb/gs_usb.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering usb_submit_urb() failures,
    aka CID-fb5be6a7b486 (bnc#1157324).

  - CVE-2019-19067: Four memory leaks in the acp_hw_init()
    function in drivers/gpu/drm/amd/amdgpu/amdgpu_acp.c were
    fixed. (bnc#1157180).

  - CVE-2019-19060: A memory leak in the
    adis_update_scan_mode() function in
    drivers/iio/imu/adis_buffer.c allowed attackers to cause
    a denial of service (memory consumption), aka
    CID-ab612b1daf41 (bnc#1157178).

  - CVE-2019-19049: A memory leak in the unittest_data_add()
    function in drivers/of/unittest.c was fixed.
    (bnc#1157173).

  - CVE-2019-19075: A memory leak in the ca8210_probe()
    function in drivers/net/ieee802154/ca8210.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering ca8210_get_platform_data()
    failures, aka CID-6402939ec86e (bnc#1157162).

  - CVE-2019-19058: A memory leak in the alloc_sgtable()
    function in drivers/net/wireless/intel/iwlwifi/fw/dbg.c
    allowed attackers to cause a denial of service (memory
    consumption) by triggering alloc_page() failures, aka
    CID-b4b814fec1a5 (bnc#1157145).

  - CVE-2019-19074: A memory leak in the ath9k_wmi_cmd()
    function in drivers/net/wireless/ath/ath9k/wmi.c allowed
    attackers to cause a denial of service (memory
    consumption), aka CID-728c1e2a05e4 (bnc#1157143).

  - CVE-2019-19073: Memory leaks in
    drivers/net/wireless/ath/ath9k/htc_hst.c allowed
    attackers to cause a denial of service (memory
    consumption) by triggering wait_for_completion_timeout()
    failures. This affects the htc_config_pipe_credits()
    function, the htc_setup_complete() function, and the
    htc_connect_service() function, aka CID-853acf7caf10
    (bnc#1157070).

  - CVE-2019-19083: Memory leaks in *clock_source_create()
    functions under drivers/gpu/drm/amd/display/dc allowed
    attackers to cause a denial of service (memory
    consumption). This affects the
    dce112_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce112/dce112_resource.c,
    the dce100_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce100/dce100_resource.c,
    the dcn10_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dcn10/dcn10_resource.c,
    the dcn20_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dcn20/dcn20_resource.c,
    the dce120_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce120/dce120_resource.c,
    the dce110_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce110/dce110_resource.c,
    and the dce80_clock_source_create() function in
    drivers/gpu/drm/amd/display/dc/dce80/dce80_resource.c,
    aka CID-055e547478a1 (bnc#1157049).

  - CVE-2019-19082: Memory leaks in *create_resource_pool()
    functions under drivers/gpu/drm/amd/display/dc allowed
    attackers to cause a denial of service (memory
    consumption). This affects the
    dce120_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce120/dce120_resource.c,
    the dce110_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce110/dce110_resource.c,
    the dce100_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce100/dce100_resource.c,
    the dcn10_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dcn10/dcn10_resource.c,
    and the dce112_create_resource_pool() function in
    drivers/gpu/drm/amd/display/dc/dce112/dce112_resource.c,
    aka CID-104c307147ad (bnc#1157046).

  - CVE-2019-15916: There was a memory leak in
    register_queue_kobjects() in net/core/net-sysfs.c, which
    will cause denial of service (bnc#1149448).

The following non-security bugs were fixed :

  - ACPICA: Never run _REG on system_memory and system_IO
    (bsc#1051510).

  - ACPICA: Use %d for signed int print formatting instead
    of %u (bsc#1051510).

  - ACPI / hotplug / PCI: Allocate resources directly under
    the non-hotplug bridge (bsc#1111666).

  - ACPI / LPSS: Exclude I2C busses shared with PUNIT from
    pmc_atom_d3_mask (bsc#1051510).

  - acpi/nfit, device-dax: Identify differentiated memory
    with a unique numa-node (bsc#1158071).

  - ACPI / SBS: Fix rare oops when removing modules
    (bsc#1051510).

  - ALSA: 6fire: Drop the dead code (git-fixes).

  - ALSA: cs4236: fix error return comparison of an unsigned
    integer (git-fixes).

  - ALSA: firewire-motu: Correct a typo in the clock proc
    string (git-fixes).

  - ALSA: hda: Add Cometlake-S PCI ID (git-fixes).

  - ALSA: hda - Add mute led support for HP ProBook 645 G4
    (git-fixes).

  - ALSA: hda - Fix pending unsol events at shutdown
    (git-fixes).

  - ALSA: hda: Fix racy display power access (bsc#1156928).

  - ALSA: hda/hdmi - Clear codec->relaxed_resume flag at
    unbinding (git-fixes).

  - ALSA: hda: hdmi - fix port numbering for ICL and TGL
    platforms (git-fixes).

  - ALSA: hda: hdmi - remove redundant code comments
    (git-fixes).

  - ALSA: hda/intel: add CometLake PCI IDs (bsc#1156729).

  - ALSA: hda/realtek - Enable internal speaker of ASUS
    UX431FLC (git-fixes).

  - ALSA: hda/realtek - Enable the headset-mic on a Xiaomi's
    laptop (git-fixes).

  - ALSA: hda/realtek - Move some alc236 pintbls to fallback
    table (git-fixes).

  - ALSA: hda/realtek - Move some alc256 pintbls to fallback
    table (git-fixes).

  - ALSA: i2c/cs8427: Fix int to char conversion
    (bsc#1051510).

  - ALSA: intel8x0m: Register irq handler after register
    initializations (bsc#1051510).

  - ALSA: pcm: Fix stream lock usage in
    snd_pcm_period_elapsed() (git-fixes).

  - ALSA: pcm: signedness bug in snd_pcm_plug_alloc()
    (bsc#1051510).

  - ALSA: pcm: Yet another missing check of non-cached
    buffer type (bsc#1111666).

  - ALSA: seq: Do error checks at creating system ports
    (bsc#1051510).

  - ALSA: usb-audio: Add skip_validation option (git-fixes).

  - ALSA: usb-audio: Fix Focusrite Scarlett 6i6 gen1 - input
    handling (git-fixes).

  - ALSA: usb-audio: Fix incorrect NULL check in
    create_yamaha_midi_quirk() (git-fixes).

  - ALSA: usb-audio: Fix incorrect size check for
    processing/extension units (git-fixes).

  - ALSA: usb-audio: Fix missing error check at mixer
    resolution test (git-fixes).

  - ALSA: usb-audio: Fix NULL dereference at parsing BADD
    (git-fixes).

  - ALSA: usb-audio: not submit urb for stopped endpoint
    (git-fixes).

  - ALSA: usb-audio: sound: usb: usb true/false for bool
    return type (git-fixes).

  - appledisplay: fix error handling in the scheduled work
    (git-fixes).

  - arm64: Update config files. (bsc#1156466) Enable
    HW_RANDOM_OMAP driver and mark driver omap-rng as
    supported.

  - ASoC: davinci: Kill BUG_ON() usage (stable 4.14.y).

  - ASoC: davinci-mcasp: Handle return value of
    devm_kasprintf (stable 4.14.y).

  - ASoC: dpcm: Properly initialise hw->rate_max
    (bsc#1051510).

  - ASoC: Intel: hdac_hdmi: Limit sampling rates at dai
    creation (bsc#1051510).

  - ASoC: kirkwood: fix external clock probe defer
    (git-fixes).

  - ASoC: msm8916-wcd-analog: Fix RX1 selection in RDAC2 MUX
    (git-fixes).

  - ASoC: sgtl5000: avoid division by zero if lo_vag is zero
    (bsc#1051510).

  - ASoC: tegra_sgtl5000: fix device_node refcounting
    (bsc#1051510).

  - ASoC: tlv320aic31xx: Handle inverted BCLK in non-DSP
    modes (stable 4.14.y).

  - ASoC: tlv320dac31xx: mark expected switch fall-through
    (stable 4.14.y).

  - ata: ep93xx: Use proper enums for directions
    (bsc#1051510).

  - ath10k: allocate small size dma memory in
    ath10k_pci_diag_write_mem (bsc#1111666).

  - ath10k: avoid possible memory access violation
    (bsc#1111666).

  - ath10k: Correct error handling of dma_map_single()
    (bsc#1111666).

  - ath10k: fix kernel panic by moving pci flush after
    napi_disable (bsc#1051510).

  - ath10k: fix vdev-start timeout on error (bsc#1051510).

  - ath10k: limit available channels via DT
    ieee80211-freq-limit (bsc#1051510).

  - ath10k: skip resetting rx filter for WCN3990
    (bsc#1111666).

  - ath10k: wmi: disable softirq's while calling
    ieee80211_rx (bsc#1051510).

  - ath9k: add back support for using active monitor
    interfaces for tx99 (bsc#1051510).

  - ath9k: Fix a locking bug in ath9k_add_interface()
    (bsc#1051510).

  - ath9k: fix reporting calculated new FFT upper max
    (bsc#1051510).

  - ath9k: fix tx99 with monitor mode interface
    (bsc#1051510).

  - ath9k_hw: fix uninitialized variable data (bsc#1051510).

  - ax88172a: fix information leak on short answers
    (bsc#1051510).

  - backlight: lm3639: Unconditionally call
    led_classdev_unregister (bsc#1051510).

  - Bluetooth: btusb: fix PM leak in error case of setup
    (bsc#1051510).

  - Bluetooth: delete a stray unlock (bsc#1051510).

  - Bluetooth: Fix invalid-free in bcsp_close() (git-fixes).

  - Bluetooth: Fix memory leak in hci_connect_le_scan
    (bsc#1051510).

  - Bluetooth: hci_core: fix init for HCI_USER_CHANNEL
    (bsc#1051510).

  - Bluetooth: L2CAP: Detect if remote is not able to use
    the whole MPS (bsc#1051510).

  - bnxt_en: Increase timeout for HWRM_DBG_COREDUMP_XX
    commands (bsc#1104745).

  - bnxt_en: Increase timeout for HWRM_DBG_COREDUMP_XX
    commands (bsc#1104745 FATE#325918).

  - bnxt_en: Update firmware interface spec. to 1.10.0.47
    (bsc#1157115)

  - bnxt_en: Update firmware interface spec. to 1.10.0.89
    (bsc#1157115)

  - bnxt_en: Update firmware interface to 1.10.0.69
    (bsc#1157115)

  - bpf: fix BTF limits (bsc#1109837).

  - bpf: fix BTF verification of enums (bsc#1109837).

  - bpf: Fix use after free in subprog's jited symbol
    removal (bsc#1109837).

  - brcmfmac: fix full timeout waiting for action frame
    on-channel tx (bsc#1051510).

  - brcmfmac: fix wrong strnchr usage (bsc#1111666).

  - brcmfmac: increase buffer for obtaining firmware
    capabilities (bsc#1111666).

  - brcmfmac: reduce timeout for action frame scan
    (bsc#1051510).

  - brcmsmac: AP mode: update beacon when TIM changes
    (bsc#1051510).

  - brcmsmac: never log 'tid x is not agg'able' by default
    (bsc#1051510).

  - brcmsmac: Use kvmalloc() for ucode allocations
    (bsc#1111666).

  - btrfs: fix log context list corruption after rename
    exchange operation (bsc#1156494).

  - can: c_can: c_can_poll(): only read status register
    after status IRQ (git-fixes).

  - can: mcba_usb: fix use-after-free on disconnect
    (git-fixes).

  - can: peak_usb: fix a potential out-of-sync while
    decoding packets (git-fixes).

  - can: peak_usb: fix slab info leak (git-fixes).

  - can: rx-offload: can_rx_offload_offload_one(): do not
    increase the skb_queue beyond skb_queue_len_max
    (git-fixes).

  - can: rx-offload: can_rx_offload_queue_sorted(): fix
    error handling, avoid skb mem leak (git-fixes).

  - can: rx-offload: can_rx_offload_queue_tail(): fix error
    handling, avoid skb mem leak (git-fixes).

  - can: usb_8dev: fix use-after-free on disconnect
    (git-fixes).

  - ceph: add missing check in d_revalidate snapdir handling
    (bsc#1157183).

  - ceph: do not try to handle hashed dentries in
    non-O_CREAT atomic_open (bsc#1157184).

  - ceph: fix use-after-free in __ceph_remove_cap()
    (bsc#1154058).

  - ceph: just skip unrecognized info in
    ceph_reply_info_extra (bsc#1157182).

  - cfg80211: Avoid regulatory restore when
    COUNTRY_IE_IGNORE is set (bsc#1051510).

  - cfg80211: call disconnect_wk when AP stops
    (bsc#1051510).

  - cfg80211: Prevent regulatory restore during STA
    disconnect in concurrent interfaces (bsc#1051510).

  - cfg80211: validate wmm rule when setting (bsc#1111666).

  - cgroup,writeback: do not switch wbs immediately on dead
    wbs if the memcg is dead (bsc#1158645).

  - cifs: add a helper to find an existing readable handle
    to a file (bsc#1144333, bsc#1154355).

  - cifs: avoid using MID 0xFFFF (bsc#1144333, bsc#1154355).

  - cifs: create a helper to find a writeable handle by path
    name (bsc#1144333, bsc#1154355).

  - cifs: Fix cifsInodeInfo lock_sem deadlock when reconnect
    occurs (bsc#1144333, bsc#1154355).

  - cifs: fix max ea value size (bsc#1144333, bsc#1154355).

  - cifs: Fix missed free operations (bsc#1144333,
    bsc#1154355).

  - cifs: Fix oplock handling for SMB 2.1+ protocols
    (bsc#1144333, bsc#1154355).

  - cifs: Fix retry mid list corruption on reconnects
    (bsc#1144333, bsc#1154355).

  - cifs: Fix SMB2 oplock break processing (bsc#1144333,
    bsc#1154355).

  - cifs: Fix use after free of file info structures
    (bsc#1144333, bsc#1154355).

  - cifs: Force reval dentry if LOOKUP_REVAL flag is set
    (bsc#1144333, bsc#1154355).

  - cifs: Force revalidate inode when dentry is stale
    (bsc#1144333, bsc#1154355).

  - cifs: Gracefully handle QueryInfo errors during open
    (bsc#1144333, bsc#1154355).

  - cifs: move cifsFileInfo_put logic into a work-queue
    (bsc#1144333, bsc#1154355).

  - cifs: prepare SMB2_Flush to be usable in compounds
    (bsc#1144333, bsc#1154355).

  - cifs: set domainName when a domain-key is used in
    multiuser (bsc#1144333, bsc#1154355).

  - cifs: use cifsInodeInfo->open_file_lock while iterating
    to avoid a panic (bsc#1144333, bsc#1154355).

  - cifs: use existing handle for compound_op(OP_SET_INFO)
    when possible (bsc#1144333, bsc#1154355).

  - cifs: Use kzfree() to zero out the password
    (bsc#1144333, bsc#1154355).

  - clk: at91: avoid sleeping early (git-fixes).

  - clk: pxa: fix one of the pxa RTC clocks (bsc#1051510).

  - clk: samsung: exynos5420: Preserve CPU clocks
    configuration during suspend/resume (bsc#1051510).

  - clk: samsung: exynos5420: Preserve PLL configuration
    during suspend/resume (git-fixes).

  - clk: samsung: Use clk_hw API for calling clk framework
    from clk notifiers (bsc#1051510).

  - clk: sunxi-ng: a80: fix the zero'ing of bits 16 and 18
    (git-fixes).

  - clocksource/drivers/sh_cmt: Fix clocksource width for
    32-bit machines (bsc#1051510).

  - clocksource/drivers/sh_cmt: Fixup for 64-bit machines
    (bsc#1051510).

  - compat_ioctl: handle SIOCOUTQNSD (bsc#1051510).

  - component: fix loop condition to call unbind() if bind()
    fails (bsc#1051510).

  - cpufreq: intel_pstate: Register when ACPI PCCH is
    present (bsc#1051510).

  - cpufreq/pasemi: fix use-after-free in
    pas_cpufreq_cpu_init() (bsc#1051510).

  - cpufreq: powernv: fix stack bloat and hard limit on
    number of CPUs (bsc#1051510).

  - cpufreq: Skip cpufreq resume if it's not suspended
    (bsc#1051510).

  - cpufreq: ti-cpufreq: add missing of_node_put()
    (bsc#1051510).

  - cpupower: Fix coredump on VMware (bsc#1051510).

  - cpupower : Fix cpupower working when cpu0 is offline
    (bsc#1051510).

  - cpupower : frequency-set -r option misses the last cpu
    in related cpu list (bsc#1051510).

  - crypto: af_alg - cast ki_complete ternary op to int
    (bsc#1051510).

  - crypto: crypto4xx - fix double-free in
    crypto4xx_destroy_sdr (bsc#1051510).

  - crypto: ecdh - fix big endian bug in ECC library
    (bsc#1051510).

  - crypto: fix a memory leak in rsa-kcs1pad's encryption
    mode (bsc#1051510).

  - crypto: geode-aes - switch to skcipher for cbc(aes)
    fallback (bsc#1051510).

  - crypto: mxs-dcp - Fix AES issues (bsc#1051510).

  - crypto: mxs-dcp - Fix SHA null hashes and output length
    (bsc#1051510).

  - crypto: mxs-dcp - make symbols 'sha1_null_hash' and
    'sha256_null_hash' static (bsc#1051510).

  - crypto: s5p-sss: Fix Fix argument list alignment
    (bsc#1051510).

  - crypto: tgr192 - remove unneeded semicolon
    (bsc#1051510).

  - cw1200: Fix a signedness bug in cw1200_load_firmware()
    (bsc#1051510).

  - cxgb4: fix panic when attaching to ULD fail
    (networking-stable-19_11_05).

  - cxgb4: request the TX CIDX updates to status page
    (bsc#1127354 bsc#1127371).

  - dccp: do not leak jiffies on the wire
    (networking-stable-19_11_05).

  - dlm: do not leak kernel pointer to userspace
    (bsc#1051510).

  - dlm: fix invalid free (bsc#1051510).

  - dmaengine: dma-jz4780: Do not depend on MACH_JZ4780
    (bsc#1051510).

  - dmaengine: dma-jz4780: Further residue status fix
    (bsc#1051510).

  - dmaengine: ep93xx: Return proper enum in
    ep93xx_dma_chan_direction (bsc#1051510).

  - dmaengine: imx-sdma: fix use-after-free on probe error
    path (bsc#1051510).

  - dmaengine: rcar-dmac: set scatter/gather max segment
    size (bsc#1051510).

  - dmaengine: timb_dma: Use proper enum in td_prep_slave_sg
    (bsc#1051510).

  - docs: move protection-keys.rst to the core-api book
    (bsc#1078248).

  - docs: move protection-keys.rst to the core-api book
    (FATE#322447, bsc#1078248).

  - Documentation: debugfs: Document debugfs helper for
    unsigned long values (git-fixes).

  - Documentation: x86: convert protection-keys.txt to reST
    (bsc#1078248).

  - Documentation: x86: convert protection-keys.txt to reST
    (FATE#322447, bsc#1078248).

  - drm/amdgpu: fix bad DMA from INTERRUPT_CNTL2
    (bsc#1111666).

  - drm/amd/powerplay: issue no PPSMC_MSG_GetCurrPkgPwr on
    unsupported (bsc#1113956)

  - drm/etnaviv: fix dumping of iommuv2 (bsc#1113722)

  - drm: fix module name in edid_firmware log message
    (bsc#1113956)

  - drm/i915: Do not dereference request if it may have been
    retired when (bsc#1142635)

  - drm/i915: Fix and improve MCR selection logic
    (bsc#1112178)

  - drm/i915/gvt: fix dropping obj reference twice
    (bsc#1111666).

  - drm/i915: Lock the engine while dumping the active
    request (bsc#1142635)

  - drm/i915/pmu: 'Frequency' is reported as accumulated
    cycles (bsc#1112178)

  - drm/i915: Reacquire priolist cache after dropping the
    engine lock (bsc#1129770)

  - drm/i915: Skip modeset for cdclk changes if possible
    (bsc#1156928).

  - drm/msm: fix memleak on release (bsc#1111666).

  - drm/omap: fix max fclk divider for omap36xx
    (bsc#1113722)

  - drm/radeon: fix bad DMA from INTERRUPT_CNTL2
    (git-fixes).

  - drm/radeon: fix si_enable_smc_cac() failed issue
    (bsc#1113722)

  - Drop
    scsi-qla2xxx-Fix-memory-leak-when-sending-I-O-fails.patc
    h This patch has introduces an double free. Upstream has
    dropped it from the scsi-queue before it hit mainline.
    So let's drop it as well.

  - e1000e: Drop unnecessary __E1000_DOWN bit twiddling
    (bsc#1158049).

  - e1000e: Use dev_get_drvdata where possible
    (bsc#1158049).

  - e1000e: Use rtnl_lock to prevent race conditions between
    net and pci/pm (bsc#1158049).

  - ecryptfs_lookup_interpose(): lower_dentry->d_inode is
    not stable (bsc#1158646).

  - ecryptfs_lookup_interpose(): lower_dentry->d_parent is
    not stable either (bsc#1158647).

  - EDAC/ghes: Fix locking and memory barrier issues
    (bsc#1114279). EDAC/ghes: Do not warn when incrementing
    refcount on 0 (bsc#1114279).

  - EDAC/ghes: Fix Use after free in ghes_edac remove path
    (bsc#1114279).

  - ext4: fix punch hole for inline_data file systems
    (bsc#1158640).

  - ext4: update direct I/O read lock pattern for
    IOCB_NOWAIT (bsc#1158639).

  - extcon: cht-wc: Return from default case to avoid
    warnings (bsc#1051510).

  - fbdev: sbuslib: integer overflow in
    sbusfb_ioctl_helper() (bsc#1051510).

  - fbdev: sbuslib: use checked version of put_user()
    (bsc#1051510).

  - ftrace: Introduce PERMANENT ftrace_ops flag
    (bsc#1120853).

  - gpiolib: acpi: Add Terra Pad 1061 to the
    run_edge_events_on_boot_blacklist (bsc#1051510).

  - gpio: mpc8xxx: Do not overwrite default irq_set_type
    callback (bsc#1051510).

  - gpio: syscon: Fix possible NULL ptr usage (bsc#1051510).

  - gsmi: Fix bug in append_to_eventlog sysfs handler
    (bsc#1051510).

  - HID: Add ASUS T100CHI keyboard dock battery quirks
    (bsc#1051510).

  - HID: Add quirk for Microsoft PIXART OEM mouse
    (bsc#1051510).

  - HID: asus: Add T100CHI bluetooth keyboard dock special
    keys mapping (bsc#1051510).

  - HID: Fix assumption that devices have inputs
    (git-fixes).

  - HID: wacom: generic: Treat serial number and related
    fields as unsigned (git-fixes).

  - hwmon: (ina3221) Fix INA3221_CONFIG_MODE macros
    (bsc#1051510).

  - hwmon: (pwm-fan) Silence error on probe deferral
    (bsc#1051510).

  - hwrng: omap3-rom - Call clk_disable_unprepare() on exit
    only if not idled (bsc#1051510).

  - hwrng: omap - Fix RNG wait loop timeout (bsc#1051510).

  - hypfs: Fix error number left in struct pointer member
    (bsc#1051510).

  - i2c: of: Try to find an I2C adapter matching the parent
    (bsc#1129770)

  - i40e: enable X710 support (bsc#1151067).

  - IB/mlx5: Free mpi in mp_slave mode (bsc#1103991).

  - IB/mlx5: Free mpi in mp_slave mode (bsc#1103991
    FATE#326007).

  - IB/mlx5: Support MLX5_CMD_OP_QUERY_LAG as a DEVX general
    command (bsc#1103991).

  - IB/mlx5: Support MLX5_CMD_OP_QUERY_LAG as a DEVX general
    command (bsc#1103991 FATE#326007).

  - ibmvnic: Bound waits for device queries (bsc#1155689
    ltc#182047).

  - ibmvnic: Fix completion structure initialization
    (bsc#1155689 ltc#182047).

  - ibmvnic: Serialize device queries (bsc#1155689
    ltc#182047).

  - ibmvnic: Terminate waiting device threads after loss of
    service (bsc#1155689 ltc#182047).

  - ice: fix potential infinite loop because loop counter
    being too small (bsc#1118661).

  - ice: fix potential infinite loop because loop counter
    being too small (bsc#1118661 FATE#325277).

  - iio: adc: max9611: explicitly cast gain_selectors
    (bsc#1051510).

  - iio: adc: stm32-adc: fix stopping dma (git-fixes).

  - iio: dac: mcp4922: fix error handling in
    mcp4922_write_raw (bsc#1051510).

  - iio: imu: adis16480: assign bias value only if operation
    succeeded (git-fixes).

  - iio: imu: adis16480: make sure provided frequency is
    positive (git-fixes).

  - iio: imu: adis: assign read val in debugfs hook only if
    op successful (git-fixes).

  - iio: imu: adis: assign value only if return code zero in
    read funcs (git-fixes).

  - include/linux/bitrev.h: fix constant bitrev
    (bsc#1114279).

  - inet: stop leaking jiffies on the wire
    (networking-stable-19_11_05).

  - Input: ff-memless - kill timer in destroy()
    (bsc#1051510).

  - Input: silead - try firmware reload after unsuccessful
    resume (bsc#1051510).

  - Input: st1232 - set INPUT_PROP_DIRECT property
    (bsc#1051510).

  - Input: synaptics-rmi4 - clear IRQ enables for F54
    (bsc#1051510).

  - Input: synaptics-rmi4 - destroy F54 poller workqueue
    when removing (bsc#1051510).

  - Input: synaptics-rmi4 - disable the relative position
    IRQ in the F12 driver (bsc#1051510).

  - Input: synaptics-rmi4 - do not consume more data than we
    have (F11, F12) (bsc#1051510).

  - Input: synaptics-rmi4 - fix video buffer size
    (git-fixes).

  - intel_th: Fix a double put_device() in error path
    (git-fixes).

  - iomap: Fix pipe page leakage during splicing
    (bsc#1158651).

  - iommu/vt-d: Fix QI_DEV_IOTLB_PFSID and
    QI_DEV_EIOTLB_PFSID macros (bsc#1158063).

  - ipmi:dmi: Ignore IPMI SMBIOS entries with a zero base
    address (bsc#1051510).

  - ipv4: Return -ENETUNREACH if we can't create route but
    saddr is valid (networking-stable-19_10_24).

  - irqdomain: Add the missing assignment of domain->fwnode
    for named fwnode (bsc#1111666).

  - iwlwifi: api: annotate compressed BA notif array sizes
    (bsc#1051510).

  - iwlwifi: check kasprintf() return value (bsc#1051510).

  - iwlwifi: drop packets with bad status in CD
    (bsc#1111666).

  - iwlwifi: mvm: avoid sending too many BARs (bsc#1051510).

  - iwlwifi: mvm: do not send keys when entering D3
    (bsc#1051510).

  - iwlwifi: mvm: use correct FIFO length (bsc#1111666).

  - iwlwifi: pcie: fit reclaim msg to MAX_MSG_LEN
    (bsc#1111666).

  - iwlwifi: pcie: read correct prph address for newer
    devices (bsc#1111666).

  - ixgbe: fix double clean of Tx descriptors with xdp
    (bsc#1113994 ).

  - ixgbe: fix double clean of Tx descriptors with xdp
    (bsc#1113994 FATE#326315 FATE#326317).

  - ixgbevf: Fix secpath usage for IPsec Tx offload
    (bsc#1113994 ).

  - ixgbevf: Fix secpath usage for IPsec Tx offload
    (bsc#1113994 FATE#326315 FATE#326317).

  - kABI: Fix for 'KVM: x86: Introduce
    vcpu->arch.xsaves_enabled' (bsc#1158066).

  - kABI fixup alloc_dax_region (bsc#1158071).

  - kabi: s390: struct subchannel (git-fixes).

  - kABI workaround for ath10k hw_filter_reset_required
    field (bsc#1111666).

  - kABI workaround for ath10k last_wmi_vdev_start_status
    field (bsc#1051510).

  - kABI workaround for iwlwifi iwl_rx_cmd_buffer change
    (bsc#1111666).

  - kABI workaround for struct mwifiex_power_cfg change
    (bsc#1051510).

  - KVM: s390: fix __insn32_query() inline assembly
    (git-fixes).

  - KVM: s390: vsie: Do not shadow CRYCB when no AP and no
    keys (git-fixes).

  - KVM: s390: vsie: Return correct values for Invalid CRYCB
    format (git-fixes).

  - KVM: SVM: Guard against DEACTIVATE when performing
    WBINVD/DF_FLUSH (bsc#1114279).

  - KVM: SVM: Serialize access to the SEV ASID bitmap
    (bsc#1114279).

  - KVM: VMX: Consider PID.PIR to determine if vCPU has
    pending interrupts (bsc#1158064).

  - KVM: VMX: Fix conditions for guest IA32_XSS support
    (bsc#1158065).

  - KVM: x86: Introduce vcpu->arch.xsaves_enabled
    (bsc#1158066).

  - KVM: x86/mmu: Take slots_lock when using
    kvm_mmu_zap_all_fast() (bsc#1158067).

  - libnvdimm: Export the target_node attribute for regions
    and namespaces (bsc#1158071).

  - lib/scatterlist: Fix chaining support in
    sgl_alloc_order() (git-fixes).

  - lib/scatterlist: Introduce sgl_alloc() and sgl_free()
    (git-fixes).

  - liquidio: fix race condition in instruction completion
    processing (bsc#1051510).

  - livepatch: Allow to distinguish different version of
    system state changes (bsc#1071995).

  - livepatch: Allow to distinguish different version of
    system state changes (bsc#1071995 fate#323487).

  - livepatch: Basic API to track system state changes
    (bsc#1071995 ).

  - livepatch: Basic API to track system state changes
    (bsc#1071995 fate#323487).

  - livepatch: Keep replaced patches until post_patch
    callback is called (bsc#1071995).

  - livepatch: Keep replaced patches until post_patch
    callback is called (bsc#1071995 fate#323487).

  - livepatch: Selftests of the API for tracking system
    state changes (bsc#1071995).

  - livepatch: Selftests of the API for tracking system
    state changes (bsc#1071995 fate#323487).

  - loop: add ioctl for changing logical block size
    (bsc#1108043).

  - loop: fix no-unmap write-zeroes request behavior
    (bsc#1158637).

  - lpfc: size cpu map by last cpu id set (bsc#1157160).

  - mac80211: consider QoS Null frames for
    STA_NULLFUNC_ACKED (bsc#1051510).

  - mac80211: minstrel: fix CCK rate group streams value
    (bsc#1051510).

  - mac80211: minstrel: fix sampling/reporting of CCK rates
    in HT mode (bsc#1051510).

  - macvlan: schedule bc_work even if error (bsc#1051510).

  - mailbox: reset txdone_method TXDONE_BY_POLL if client
    knows_txdone (git-fixes).

  - media: au0828: Fix incorrect error messages
    (bsc#1051510).

  - media: bdisp: fix memleak on release (git-fixes).

  - media: cxusb: detect cxusb_ctrl_msg error in query
    (bsc#1051510).

  - media: davinci: Fix implicit enum conversion warning
    (bsc#1051510).

  - media: exynos4-is: Fix recursive locking in
    isp_video_release() (git-fixes).

  - media: fix: media: pci: meye: validate offset to avoid
    arbitrary access (bsc#1051510).

  - media: flexcop-usb: ensure -EIO is returned on error
    condition (git-fixes).

  - media: imon: invalid dereference in imon_touch_event
    (bsc#1051510).

  - media: isif: fix a NULL pointer dereference bug
    (bsc#1051510).

  - media: pci: ivtv: Fix a sleep-in-atomic-context bug in
    ivtv_yuv_init() (bsc#1051510).

  - media: pxa_camera: Fix check for pdev->dev.of_node
    (bsc#1051510).

  - media: radio: wl1273: fix interrupt masking on release
    (git-fixes).

  - media: ti-vpe: vpe: Fix Motion Vector vpdma stride
    (git-fixes).

  - media: usbvision: Fix races among open, close, and
    disconnect (bsc#1051510).

  - media: vim2m: Fix abort issue (git-fixes).

  - media: vivid: Set vid_cap_streaming and
    vid_out_streaming to true (bsc#1051510).

  - mei: fix modalias documentation (git-fixes).

  - mei: samples: fix a signedness bug in amt_host_if_call()
    (bsc#1051510).

  - mfd: intel-lpss: Add default I2C device properties for
    Gemini Lake (bsc#1051510).

  - mfd: max8997: Enale irq-wakeup unconditionally
    (bsc#1051510).

  - mfd: mc13xxx-core: Fix PMIC shutdown when reading ADC
    values (bsc#1051510).

  - mfd: palmas: Assign the right powerhold mask for
    tps65917 (git-fixes).

  - mfd: ti_am335x_tscadc: Keep ADC interface on if child is
    wakeup capable (bsc#1051510).

  - mISDN: Fix type of switch control variable in
    ctrl_teimanager (bsc#1051510).

  - mlx5: add parameter to disable enhanced IPoIB
    (bsc#1142095)

  - mlx5: add parameter to disable enhanced IPoIB
    (bsc#1142095) Fix badly backported patch

  - mlxsw: spectrum_flower: Fail in case user specifies
    multiple mirror actions (bsc#1112374).

  - mmc: core: fix wl1251 sdio quirks (git-fixes).

  - mmc: host: omap_hsmmc: add code for special init of
    wl1251 to get rid of pandora_wl1251_init_card
    (git-fixes).

  - mmc: mediatek: fix cannot receive new request when
    msdc_cmd_is_ready fail (bsc#1051510).

  - mm/compaction.c: clear total_(migrate,free)_scanned
    before scanning a new zone (git fixes (mm/compaction)).

  - mmc: sdhci-esdhc-imx: correct the fix of ERR004536
    (git-fixes).

  - mmc: sdhci-of-at91: fix quirk2 overwrite (git-fixes).

  - mmc: sdio: fix wl1251 vendor id (git-fixes).

  - mm/debug.c: PageAnon() is true for PageKsm() pages (git
    fixes (mm/debug)).

  - mm, thp: Do not make page table dirty unconditionally in
    touch_p[mu]d() (git fixes (mm/gup)).

  - mt7601u: fix bbp version check in mt7601u_wait_bbp_ready
    (bsc#1051510).

  - mt76x0: init hw capabilities.

  - mtd: nand: mtk: fix incorrect register setting order
    about ecc irq.

  - mtd: spear_smi: Fix Write Burst mode (bsc#1051510).

  - mtd: spi-nor: fix silent truncation in spi_nor_read()
    (bsc#1051510).

  - mwifex: free rx_cmd skb in suspended state
    (bsc#1111666).

  - mwifiex: do no submit URB in suspended state
    (bsc#1111666).

  - mwifiex: Fix NL80211_TX_POWER_LIMITED (bsc#1051510).

  - nbd: prevent memory leak (bsc#1158638).

  - net: add READ_ONCE() annotation in
    __skb_wait_for_more_packets()
    (networking-stable-19_11_05).

  - net: add skb_queue_empty_lockless()
    (networking-stable-19_11_05).

  - net: annotate accesses to sk->sk_incoming_cpu
    (networking-stable-19_11_05).

  - net: annotate lockless accesses to sk->sk_napi_id
    (networking-stable-19_11_05).

  - net: avoid potential infinite loop in tc_ctl_action()
    (networking-stable-19_10_24).

  - net: bcmgenet: Fix RGMII_MODE_EN value for GENET v1/2/3
    (networking-stable-19_10_24).

  - net: bcmgenet: reset 40nm EPHY on energy detect
    (networking-stable-19_11_05).

  - net: bcmgenet: Set phydev->dev_flags only for internal
    PHYs (networking-stable-19_10_24).

  - net: dsa: b53: Do not clear existing mirrored port mask
    (networking-stable-19_11_05).

  - net: dsa: bcm_sf2: Fix IMP setup for port different than
    8 (networking-stable-19_11_05).

  - net: dsa: fix switch tree list
    (networking-stable-19_11_05).

  - net: ethernet: ftgmac100: Fix DMA coherency issue with
    SW checksum (networking-stable-19_11_05).

  - net: fix sk_page_frag() recursion from memory reclaim
    (networking-stable-19_11_05).

  - net: hisilicon: Fix ping latency when deal with high
    throughput (networking-stable-19_11_05).

  - net: hns3: change GFP flag during lock period
    (bsc#1104353 ).

  - net: hns3: change GFP flag during lock period
    (bsc#1104353 FATE#326415).

  - net: hns3: do not query unsupported commands in debugfs
    (bsc#1104353).

  - net: hns3: do not query unsupported commands in debugfs
    (bsc#1104353 FATE#326415).

  - net: hns3: fix GFP flag error in
    hclge_mac_update_stats() (bsc#1126390).

  - net: hns3: fix some reset handshake issue (bsc#1104353
    ).

  - net: hns3: fix some reset handshake issue (bsc#1104353
    FATE#326415).

  - net: hns3: prevent unnecessary MAC TNL interrupt
    (bsc#1104353 bsc#1134983).

  - net: hns3: prevent unnecessary MAC TNL interrupt
    (bsc#1104353 FATE#326415 bsc#1134983).

  - net: hns: Fix the stray netpoll locks causing deadlock
    in NAPI path (bsc#1104353).

  - net: hns: Fix the stray netpoll locks causing deadlock
    in NAPI path (bsc#1104353 FATE#326415).

  - net/ibmvnic: Ignore H_FUNCTION return from H_EOI to
    tolerate XIVE mode (bsc#1089644, ltc#166495, ltc#165544,
    git-fixes).

  - net/mlx4_core: Dynamically set guaranteed amount of
    counters per VF (networking-stable-19_11_05).

  - net/mlx5e: Fix eswitch debug print of max fdb flow
    (bsc#1103990 ).

  - net/mlx5e: Fix eswitch debug print of max fdb flow
    (bsc#1103990 FATE#326006).

  - net/mlx5e: Fix ethtool self test: link speed
    (bsc#1103990 ).

  - net/mlx5e: Fix ethtool self test: link speed
    (bsc#1103990 FATE#326006).

  - net/mlx5e: Fix handling of compressed CQEs in case of
    low NAPI budget (networking-stable-19_11_05).

  - net/mlx5e: Print a warning when LRO feature is dropped
    or not allowed (bsc#1103990).

  - net/mlx5e: Print a warning when LRO feature is dropped
    or not allowed (bsc#1103990 FATE#326006).

  - net/mlx5: FWTrace, Reduce stack usage (bsc#1103990).

  - net/mlx5: FWTrace, Reduce stack usage (bsc#1103990
    FATE#326006).

  - netns: fix GFP flags in rtnl_net_notifyid()
    (networking-stable-19_11_05).

  - net: phy: bcm7xxx: define soft_reset for 40nm EPHY
    (bsc#1119113 ).

  - net: phy: bcm7xxx: define soft_reset for 40nm EPHY
    (bsc#1119113 FATE#326472).

  - net: phylink: Fix flow control resolution (bsc#1119113
    ).

  - net: phylink: Fix flow control resolution (bsc#1119113
    FATE#326472).

  - net: sched: cbs: Avoid division by zero when calculating
    the port rate (bsc#1109837).

  - net/sched: cbs: Fix not adding cbs instance to list
    (bsc#1109837).

  - net/sched: cbs: Set default link speed to 10 Mbps in
    cbs_set_port_rate (bsc#1109837).

  - net: sched: fix possible crash in tcf_action_destroy()
    (bsc#1109837).

  - net: sched: fix reordering issues (bsc#1109837).

  - net/smc: avoid fallback in case of non-blocking connect
    (git-fixes).

  - net/smc: do not schedule tx_work in SMC_CLOSED state
    (git-fixes).

  - net/smc: fix closing of fallback SMC sockets
    (git-fixes).

  - net/smc: Fix error path in smc_init (git-fixes).

  - net/smc: fix ethernet interface refcounting (git-fixes).

  - net/smc: fix fastopen for non-blocking connect()
    (git-fixes).

  - net/smc: fix refcounting for non-blocking connect()
    (git-fixes).

  - net/smc: fix refcount non-blocking connect() -part 2
    (git-fixes).

  - net/smc: fix SMCD link group creation with VLAN id
    (git-fixes).

  - net/smc: keep vlan_id for SMC-R in smc_listen_work()
    (git-fixes).

  - net/smc: original socket family in inet_sock_diag
    (git-fixes).

  - net: sock_map, fix missing ulp check in sock hash case
    (bsc#1109837).

  - net: stmmac: disable/enable ptp_ref_clk in
    suspend/resume flow (networking-stable-19_10_24).

  - net: use skb_queue_empty_lockless() in busy poll
    contexts (networking-stable-19_11_05).

  - net: use skb_queue_empty_lockless() in poll() handlers
    (networking-stable-19_11_05).

  - net: wireless: ti: remove local VENDOR_ID and DEVICE_ID
    definitions (git-fixes).

  - net: wireless: ti: wl1251 use new
    SDIO_VENDOR_ID_TI_WL1251 definition (git-fixes).

  - net: Zeroing the structure ethtool_wolinfo in
    ethtool_get_wol() (networking-stable-19_11_05).

  - nfc: netlink: fix double device reference drop
    (git-fixes).

  - NFC: nxp-nci: Fix NULL pointer dereference after I2C
    communication error (git-fixes).

  - nfc: port100: handle command failure cleanly
    (git-fixes).

  - nfp: flower: fix memory leak in
    nfp_flower_spawn_vnic_reprs (bsc#1109837).

  - nfp: flower: prevent memory leak in
    nfp_flower_spawn_phy_reprs (bsc#1109837).

  - nl80211: Fix a GET_KEY reply attribute (bsc#1051510).

  - nvme-tcp: support C2HData with SUCCESS flag
    (bsc#1157386).

  - ocfs2: fix panic due to ocfs2_wq is null (bsc#1158644).

  - ocfs2: fix passing zero to 'PTR_ERR' warning
    (bsc#1158649).

  - openvswitch: fix flow command message size (git-fixes).

  - padata: use smp_mb in padata_reorder to avoid orphaned
    padata jobs (git-fixes).

  - PCI/ACPI: Correct error message for ASPM disabling
    (bsc#1051510).

  - PCI: Apply Cavium ACS quirk to ThunderX2 and ThunderX3
    (bsc#1051510).

  - PCI: dwc: Fix find_next_bit() usage (bsc#1051510).

  - PCI: Fix Intel ACS quirk UPDCR register address
    (bsc#1051510).

  - PCI/MSI: Fix incorrect MSI-X masking on resume
    (bsc#1051510).

  - PCI: pciehp: Do not disable interrupt twice on suspend
    (bsc#1111666).

  - PCI/PM: Clear PCIe PME Status even for legacy power
    management (bsc#1111666).

  - PCI/PME: Fix possible use-after-free on remove
    (git-fixes).

  - PCI/PTM: Remove spurious 'd' from granularity message
    (bsc#1051510).

  - PCI: rcar: Fix missing MACCTLR register setting in
    initialization sequence (bsc#1051510).

  - PCI: sysfs: Ignore lockdep for remove attribute
    (git-fixes).

  - PCI: tegra: Enable Relaxed Ordering only for Tegra20 &
    Tegra30 (git-fixes).

  - perf/x86/amd: Change/fix NMI latency mitigation to use a
    timestamp (bsc#1142924).

  - phy: phy-twl4030-usb: fix denied runtime access
    (git-fixes).

  - pinctl: ti: iodelay: fix error checking on
    pinctrl_count_index_with_args call (git-fixes).

  - pinctrl: at91: do not use the same irqchip with multiple
    gpiochips (git-fixes).

  - pinctrl: cherryview: Allocate IRQ chip dynamic
    (git-fixes).

  - pinctrl: lewisburg: Update pin list according to v1.1v6
    (bsc#1051510).

  - pinctrl: lpc18xx: Use define directive for
    PIN_CONFIG_GPIO_PIN_INT (bsc#1051510).

  - pinctrl: qcom: spmi-gpio: fix gpio-hog related boot
    issues (bsc#1051510).

  - pinctrl: samsung: Fix device node refcount leaks in init
    code (bsc#1051510).

  - pinctrl: samsung: Fix device node refcount leaks in
    S3C24xx wakeup controller init (bsc#1051510).

  - pinctrl: samsung: Fix device node refcount leaks in
    S3C64xx wakeup controller init (bsc#1051510).

  - pinctrl: sunxi: Fix a memory leak in
    'sunxi_pinctrl_build_state()' (bsc#1051510).

  - pinctrl: zynq: Use define directive for
    PIN_CONFIG_IO_STANDARD (bsc#1051510).

  - PM / devfreq: Check NULL governor in
    available_governors_show (git-fixes).

  - PM / devfreq: exynos-bus: Correct clock enable sequence
    (bsc#1051510).

  - PM / devfreq: Lock devfreq in trans_stat_show
    (git-fixes).

  - PM / devfreq: passive: fix compiler warning
    (bsc#1051510).

  - PM / devfreq: passive: Use non-devm notifiers
    (bsc#1051510).

  - PM / hibernate: Check the success of generating md5
    digest before hibernation (bsc#1051510).

  - powerpc/64: Make meltdown reporting Book3S 64 specific
    (bsc#1091041).

  - powerpc/book3s64/hash: Use secondary hash for bolted
    mapping if the primary is full (bsc#1157778 ltc#182520).

  - powerpc/bpf: Fix tail call implementation (bsc#1157698).

  - powerpc/pseries: address checkpatch warnings in
    dlpar_offline_cpu (bsc#1156700 ltc#182459).

  - powerpc/pseries: Do not fail hash page table insert for
    bolted mapping (bsc#1157778 ltc#182520).

  - powerpc/pseries: Do not opencode HPTE_V_BOLTED
    (bsc#1157778 ltc#182520).

  - powerpc/pseries: safely roll back failed DLPAR cpu add
    (bsc#1156700 ltc#182459).

  - powerpc/security/book3s64: Report L1TF status in sysfs
    (bsc#1091041).

  - powerpc/security: Fix wrong message when RFI Flush is
    disable (bsc#1131107).

  - powerpc/xive: Prevent page fault issues in the machine
    crash handler (bsc#1156882 ltc#182435).

  - power: reset: at91-poweroff: do not procede if
    at91_shdwc is allocated (bsc#1051510).

  - power: supply: ab8500_fg: silence uninitialized variable
    warnings (bsc#1051510).

  - power: supply: twl4030_charger: disable eoc interrupt on
    linear charge (bsc#1051510).

  - power: supply: twl4030_charger: fix charging current
    out-of-bounds (bsc#1051510).

  - ppdev: fix PPGETTIME/PPSETTIME ioctls (bsc#1051510).

  - printk: Export console_printk (bsc#1071995).

  - printk: Export console_printk (bsc#1071995 fate#323487).

  - pwm: bcm-iproc: Prevent unloading the driver module
    while in use (git-fixes).

  - pwm: lpss: Only set update bit if we are actually
    changing the settings (bsc#1051510).

  - qxl: fix NULL pointer crash during suspend
    (bsc#1111666).

  - r8152: add device id for Lenovo ThinkPad USB-C Dock Gen
    2 (networking-stable-19_11_05).

  - RDMA/bnxt_re: Fix stat push into dma buffer on gen p5
    devices (bsc#1157115)

  - RDMA/efa: Clear the admin command buffer prior to its
    submission (git-fixes) Patch was already picked through
    Amazon driver repo but was not marked with a Git-commit
    tag

  - RDMA/hns: Fix comparison of unsigned long variable 'end'
    with less than zero (bsc#1104427 bsc#1137236).

  - RDMA/hns: Fix comparison of unsigned long variable 'end'
    with less than zero (bsc#1104427 FATE#326416
    bsc#1137236).

  - RDMA/hns: Fix wrong assignment of qp_access_flags
    (bsc#1104427 ).

  - RDMA/hns: Fix wrong assignment of qp_access_flags
    (bsc#1104427 FATE#326416).

  - regulator: ab8500: Remove AB8505 USB regulator
    (bsc#1051510).

  - regulator: ab8500: Remove SYSCLKREQ from enum
    ab8505_regulator_id (bsc#1051510).

  - remoteproc: Check for NULL firmwares in sysfs interface
    (git-fixes).

  - Remove patches that reportedly cause regression
    (bsc#1155689 ltc#182047).

  - reset: fix of_reset_simple_xlate kerneldoc comment
    (bsc#1051510).

  - reset: Fix potential use-after-free in
    __of_reset_control_get() (bsc#1051510).

  - reset: fix reset_control_get_exclusive kerneldoc comment
    (bsc#1051510).

  - Revert 'drm/etnaviv: fix dumping of iommuv2
    (bsc#1113722)' This reverts commit
    71e3a1b8d8cf73f711f3e4100aa51f68e631f94f. ATM the
    backported patch does not build on x86.

  - rpm/kernel-binary.spec.in: add COMPRESS_VMLINUX
    (bnc#1155921) Let COMPRESS_VMLINUX determine the
    compression used for vmlinux. By default (historically),
    it is gz.

  - rpm/kernel-source.spec.in: Fix dependency of
    kernel-devel (bsc#1154043)

  - rt2800: remove errornous duplicate condition
    (git-fixes).

  - rtl8187: Fix warning generated when strncpy()
    destination length matches the sixe argument
    (bsc#1051510).

  - rtlwifi: btcoex: Use proper enumerated types for Wi-Fi
    only interface (bsc#1111666).

  - rtlwifi: Remove unnecessary NULL check in rtl_regd_init
    (bsc#1051510).

  - rtlwifi: rtl8192de: Fix misleading REG_MCUFWDL
    information (bsc#1051510).

  - rtlwifi: rtl8192de: Fix missing code to retrieve RX
    buffer address (bsc#1051510).

  - rtlwifi: rtl8192de: Fix missing enable interrupt flag
    (bsc#1051510).

  - s390/bpf: fix lcgr instruction encoding (bsc#1051510).

  - s390/bpf: use 32-bit index for tail calls (bsc#1051510).

  - s390/cio: avoid calling strlen on NULL pointer
    (bsc#1051510).

  - s390/cio: exclude subchannels with no parent from pseudo
    check (bsc#1051510).

  - s390/cio: fix virtio-ccw DMA without PV (git-fixes).

  - s390/cmm: fix information leak in cmm_timeout_handler()
    (bsc#1051510).

  - s390: fix stfle zero padding (bsc#1051510).

  - s390/idle: fix cpu idle time calculation (bsc#1051510).

  - s390/mm: properly clear _PAGE_NOEXEC bit when it is not
    supported (bsc#1051510).

  - s390/process: avoid potential reading of freed stack
    (bsc#1051510).

  - s390/qdio: do not touch the dsci in
    tiqdio_add_input_queues() (bsc#1051510).

  - s390/qdio: (re-)initialize tiqdio list entries
    (bsc#1051510).

  - s390/qeth: return proper errno on IO error
    (bsc#1051510).

  - s390/setup: fix boot crash for machine without EDAT-1
    (bsc#1051510 bsc#1140948).

  - s390/setup: fix early warning messages (bsc#1051510
    bsc#1140948).

  - s390/topology: avoid firing events before kobjs are
    created (bsc#1051510).

  - s390: vsie: Use effective CRYCBD.31 to check CRYCBD
    validity (git-fixes).

  - s390/zcrypt: fix memleak at release (git-fixes).

  - scsi: lpfc: Add enablement of multiple adapter dumps
    (bsc#1154601).

  - scsi: lpfc: Add registration for CPU Offline/Online
    events (bsc#1154601).

  - scsi: lpfc: Change default IRQ model on AMD
    architectures (bsc#1154601).

  - scsi: lpfc: Clarify FAWNN error message (bsc#1154601).

  - scsi: lpfc: Fix a kernel warning triggered by
    lpfc_get_sgl_per_hdwq() (bsc#1154601).

  - scsi: lpfc: Fix a kernel warning triggered by
    lpfc_sli4_enable_intr() (bsc#1154601).

  - scsi: lpfc: fix build error of lpfc_debugfs.c for
    vfree/vmalloc (bsc#1154601).

  - scsi: lpfc: Fix configuration of BB credit recovery in
    service parameters (bsc#1154601).

  - scsi: lpfc: fix: Coverity: lpfc_cmpl_els_rsp(): NULL
    pointer dereferences (bsc#1154601).

  - scsi: lpfc: fix: Coverity: lpfc_get_scsi_buf_s3(): NULL
    pointer dereferences (bsc#1154601).

  - scsi: lpfc: Fix duplicate unreg_rpi error in port
    offline flow (bsc#1154601).

  - scsi: lpfc: Fix dynamic fw log enablement check
    (bsc#1154601).

  - scsi: lpfc: fix inlining of
    lpfc_sli4_cleanup_poll_list() (bsc#1154601).

  - scsi: lpfc: Fix kernel crash at lpfc_nvme_info_show
    during remote port bounce (bsc#1154601).

  - scsi: lpfc: Fix lpfc_cpumask_of_node_init()
    (bsc#1154601).

  - scsi: lpfc: Fix NULL check before mempool_destroy is not
    needed (bsc#1154601).

  - scsi: lpfc: Fix Oops in nvme_register with target
    logout/login (bsc#1151900).

  - scsi: lpfc: fix spelling error in MAGIC_NUMER_xxx
    (bsc#1154601).

  - scsi: lpfc: Fix unexpected error messages during RSCN
    handling (bsc#1154601).

  - scsi: lpfc: Honor module parameter lpfc_use_adisc
    (bsc#1153628).

  - scsi: lpfc: Honor module parameter lpfc_use_adisc
    (bsc#1154601).

  - scsi: lpfc: Initialize cpu_map for not present cpus
    (bsc#1154601).

  - scsi: lpfc: lpfc_attr: Fix Use plain integer as NULL
    pointer (bsc#1154601).

  - scsi: lpfc: lpfc_nvmet: Fix Use plain integer as NULL
    pointer (bsc#1154601).

  - scsi: lpfc: Make lpfc_debugfs_ras_log_data static
    (bsc#1154601).

  - scsi: lpfc: Mitigate high memory pre-allocation by
    SCSI-MQ (bsc#1154601).

  - scsi: lpfc: Raise config max for lpfc_fcp_mq_threshold
    variable (bsc#1154601).

  - scsi: lpfc: revise nvme max queues to be hdwq count
    (bsc#1154601).

  - scsi: lpfc: Sync with FC-NVMe-2 SLER change to require
    Conf with SLER (bsc#1154601).

  - scsi: lpfc: Update lpfc version to 12.6.0.1
    (bsc#1154601).

  - scsi: lpfc: Update lpfc version to 12.6.0.2
    (bsc#1154601).

  - scsi: lpfc: use hdwq assigned cpu for allocation
    (bsc#1157160).

  - scsi: qla2xxx: Add debug dump of LOGO payload and ELS
    IOCB (bsc#1157424, bsc#1157908. bsc#1117169,
    bsc#1151548).

  - scsi: qla2xxx: Allow PLOGI in target mode (bsc#1157424,
    bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Change discovery state before PLOGI
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Configure local loop for N2N target
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Do not call qlt_async_event twice
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Do not defer relogin unconditonally
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Drop superfluous INIT_WORK of del_work
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Fix PLOGI payload and ELS IOCB dump
    length (bsc#1157424, bsc#1157908. bsc#1117169,
    bsc#1151548).

  - scsi: qla2xxx: Fix qla2x00_request_irqs() for MSI
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: fix rports not being mark as lost in sync
    fabric scan (bsc#1138039).

  - scsi: qla2xxx: Ignore NULL pointer in
    tcm_qla2xxx_free_mcmd (bsc#1157424, bsc#1157908.
    bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Ignore PORT UPDATE after N2N PLOGI
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Initialize free_work before flushing it
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: Send Notify ACK after N2N PLOGI
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: qla2xxx: unregister ports after GPN_FT failure
    (bsc#1138039).

  - scsi: qla2xxx: Use correct number of vectors for online
    CPUs (bsc#1137223).

  - scsi: qla2xxx: Use explicit LOGO in target mode
    (bsc#1157424, bsc#1157908. bsc#1117169, bsc#1151548).

  - scsi: zfcp: fix request object use-after-free in send
    path causing wrong traces (bsc#1051510).

  - sctp: change sctp_prot .no_autobind with true
    (networking-stable-19_10_24).

  - sctp: fix SCTP regression (bsc#1158082)
    (networking-stable-19_10_24 bsc#1158082).

  - selftests: net: reuseport_dualstack: fix uninitalized
    parameter (networking-stable-19_11_05).

  - serial: mxs-auart: Fix potential infinite loop
    (bsc#1051510).

  - serial: samsung: Enable baud clock for UART reset
    procedure in resume (bsc#1051510).

  - serial: uartps: Fix suspend functionality (bsc#1051510).

  - signal: Properly set TRACE_SIGNAL_LOSE_INFO in
    __send_signal (bsc#1157463).

  - slcan: Fix memory leak in error path (bsc#1051510).

  - slip: Fix memory leak in slip_open error path
    (bsc#1051510).

  - slip: Fix use-after-free Read in slip_open
    (bsc#1051510).

  - smb3: fix leak in 'open on server' perf counter
    (bsc#1144333, bsc#1154355).

  - smb3: fix signing verification of large reads
    (bsc#1144333, bsc#1154355).

  - smb3: fix unmount hang in open_shroot (bsc#1144333,
    bsc#1154355).

  - smb3: improve handling of share deleted (and share
    recreated) (bsc#1144333, bsc#1154355).

  - smb3: Incorrect size for netname negotiate context
    (bsc#1144333, bsc#1154355).

  - soc: imx: gpc: fix PDN delay (bsc#1051510).

  - soc: qcom: wcnss_ctrl: Avoid string overflow
    (bsc#1051510).

  - Sort series.conf.

  - spi: atmel: Fix CS high support (bsc#1051510).

  - spi: atmel: fix handling of cs_change set on non-last
    xfer (bsc#1051510).

  - spi: fsl-lpspi: Prevent FIFO under/overrun by default
    (bsc#1051510).

  - spi: mediatek: Do not modify spi_transfer when transfer
    (bsc#1051510).

  - spi: mediatek: use correct mata->xfer_len when in fifo
    transfer (bsc#1051510).

  - spi: pic32: Use proper enum in dmaengine_prep_slave_rg
    (bsc#1051510).

  - spi: rockchip: initialize dma_slave_config properly
    (bsc#1051510).

  - spi: spidev: Fix OF tree warning logic (bsc#1051510).

  - supported.conf :

  - synclink_gt(): fix compat_ioctl() (bsc#1051510).

  - tcp_nv: fix potential integer overflow in tcpnv_acked
    (bsc#1051510).

  - thunderbolt: Fix lockdep circular locking depedency
    warning (git-fixes).

  - tipc: Avoid copying bytes beyond the supplied data
    (bsc#1051510).

  - tipc: check bearer name with right length in
    tipc_nl_compat_bearer_enable (bsc#1051510).

  - tipc: check link name with right length in
    tipc_nl_compat_link_set (bsc#1051510).

  - tipc: check msg->req data len in
    tipc_nl_compat_bearer_disable (bsc#1051510).

  - tipc: compat: allow tipc commands without arguments
    (bsc#1051510).

  - tipc: fix tipc_mon_delete() oops in tipc_enable_bearer()
    error path (bsc#1051510).

  - tipc: fix wrong timeout input for tipc_wait_for_cond()
    (bsc#1051510).

  - tipc: handle the err returned from cmd header function
    (bsc#1051510).

  - tipc: pass tunnel dev as NULL to udp_tunnel(6)_xmit_skb
    (bsc#1051510).

  - tipc: tipc clang warning (bsc#1051510).

  - tools: bpftool: fix arguments for p_err() in
    do_event_pipe() (bsc#1109837).

  - tools/power/x86/intel-speed-select: Fix a read overflow
    in isst_set_tdp_level_msr() (bsc#1111666).

  - tpm: add check after commands attribs tab allocation
    (bsc#1051510).

  - tty: serial: fsl_lpuart: use the sg count from
    dma_map_sg (bsc#1051510).

  - tty: serial: imx: use the sg count from dma_map_sg
    (bsc#1051510).

  - tty: serial: msm_serial: Fix flow control (bsc#1051510).

  - tty: serial: pch_uart: correct usage of dma_unmap_sg
    (bsc#1051510).

  - tun: fix data-race in gro_normal_list() (bsc#1111666).

  - UAS: Revert commit 3ae62a42090f ('UAS: fix alignment of
    scatter/gather segments').

  - ubifs: Correctly initialize c->min_log_bytes
    (bsc#1158641).

  - ubifs: Limit the number of pages in shrink_liability
    (bsc#1158643).

  - udp: use skb_queue_empty_lockless()
    (networking-stable-19_11_05).

  - Update
    patches.suse/ipv6-defrag-drop-non-last-frags-smaller-tha
    n-min-mtu.patch (add bsc#1141054).

  - Update
    patches.suse/RDMA-Fix-goto-target-to-release-the-allocat
    ed-memory.patch (bsc#1050244 FATE#322915 bsc#1157171
    CVE-2019-19077).

  - USB: chaoskey: fix error case of a timeout (git-fixes).

  - usb: chipidea: Fix otg event handler (bsc#1051510).

  - usb: chipidea: imx: enable OTG overcurrent in case USB
    subsystem is already started (bsc#1051510).

  - usb: dwc3: gadget: Check ENBLSLPM before sending ep
    command (bsc#1051510).

  - usb: gadget: udc: fotg210-udc: Fix a
    sleep-in-atomic-context bug in fotg210_get_status()
    (bsc#1051510).

  - usb: gadget: uvc: configfs: Drop leaked references to
    config items (bsc#1051510).

  - usb: gadget: uvc: configfs: Prevent format changes after
    linking header (bsc#1051510).

  - usb: gadget: uvc: Factor out video USB request queueing
    (bsc#1051510).

  - usb: gadget: uvc: Only halt video streaming endpoint in
    bulk mode (bsc#1051510).

  - USBIP: add config dependency for SGL_ALLOC (git-fixes).

  - usbip: Fix free of unallocated memory in vhci tx
    (git-fixes).

  - usbip: Fix vhci_urb_enqueue() URB null transfer buffer
    error path (git-fixes).

  - usbip: Implement SG support to vhci-hcd and stub driver
    (git-fixes).

  - usbip: tools: fix fd leakage in the function of
    read_attr_usbip_status (git-fixes).

  - USB: misc: appledisplay: fix backlight update_status
    return code (bsc#1051510).

  - usb-serial: cp201x: support Mark-10 digital force gauge
    (bsc#1051510).

  - USB: serial: mos7720: fix remote wakeup (git-fixes).

  - USB: serial: mos7840: add USB ID to support Moxa UPort
    2210 (bsc#1051510).

  - USB: serial: mos7840: fix remote wakeup (git-fixes).

  - USB: serial: option: add support for DW5821e with eSIM
    support (bsc#1051510).

  - USB: serial: option: add support for Foxconn T77W968 LTE
    modules (bsc#1051510).

  - usb: xhci-mtk: fix ISOC error when interval is zero
    (bsc#1051510).

  - vfio-ccw: Fix misleading comment when setting
    orb.cmd.c64 (bsc#1051510).

  - vfio: ccw: push down unsupported IDA check (bsc#1156471
    LTC#182362).

  - vfio-ccw: Set pa_nr to 0 if memory allocation fails for
    pa_iova_pfn (bsc#1051510).

  - video/hdmi: Fix AVI bar unpack (git-fixes).

  - virtio_console: allocate inbufs in add_port() only if it
    is needed (git-fixes).

  - virtio_ring: fix return code on DMA mapping fails
    (git-fixes).

  - virtio/s390: fix race on airq_areas (bsc#1051510).

  - vmxnet3: turn off lro when rxcsum is disabled
    (bsc#1157499).

  - vsock/virtio: fix sock refcnt holding during the
    shutdown (git-fixes).

  - watchdog: meson: Fix the wrong value of left time
    (bsc#1051510).

  - wil6210: drop Rx multicast packets that are looped-back
    to STA (bsc#1111666).

  - wil6210: fix debugfs memory access alignment
    (bsc#1111666).

  - wil6210: fix invalid memory access for rx_buff_mgmt
    debugfs (bsc#1111666).

  - wil6210: fix L2 RX status handling (bsc#1111666).

  - wil6210: fix locking in wmi_call (bsc#1111666).

  - wil6210: fix RGF_CAF_ICR address for Talyn-MB
    (bsc#1111666).

  - wil6210: prevent usage of tx ring 0 for eDMA
    (bsc#1111666).

  - wil6210: set edma variables only for Talyn-MB devices
    (bsc#1111666).

  - x86/alternatives: Add int3_emulate_call() selftest
    (bsc#1153811).

  - x86/alternatives: Fix int3_emulate_call() selftest stack
    corruption (bsc#1153811).

  - x86/mm/pkeys: Fix typo in
    Documentation/x86/protection-keys.txt (bsc#1078248).

  - x86/mm/pkeys: Fix typo in
    Documentation/x86/protection-keys.txt (FATE#322447,
    bsc#1078248).

  - x86/pkeys: Update documentation about availability
    (bsc#1078248).

  - x86/pkeys: Update documentation about availability
    (FATE#322447, bsc#1078248).

  - x86/resctrl: Fix potential lockdep warning
    (bsc#1114279).

  - x86/resctrl: Prevent NULL pointer dereference when
    reading mondata (bsc#1114279).

  - x86/speculation/taa: Fix printing of TAA_MSG_SMT on
    IBRS_ALL CPUs (bsc#1158068).

  - xfrm: fix sa selector validation (bsc#1156609).

  - xfrm: Fix xfrm sel prefix length validation (git-fixes).

  - xfs: Sanity check flags of Q_XQUOTARM call
    (bsc#1158652).

  - xsk: Fix registration of Rx-only sockets (bsc#1109837).

  - xsk: relax UMEM headroom alignment (bsc#1109837)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109837"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158652"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.36.1") ) flag++;

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
