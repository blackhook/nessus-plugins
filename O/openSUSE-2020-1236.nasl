#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1236.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139766);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-0305", "CVE-2020-10135", "CVE-2020-10781", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-15780", "CVE-2020-16166");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1236)");
  script_summary(english:"Check for the openSUSE-2020-1236 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The openSUSE Leap 15.2 kernel was updated to receive various security
and bugfixes.

This update is signed with the new UEFI signing key for openSUSE. It
contains rebuilds of all available KMP packages also rebuilt with the
new UEFi signing key. (boo#1174543)

The following security bugs were fixed :

  - CVE-2020-14356: A use after free vulnerability in cgroup
    BPF component was fixed (bsc#1175213).

  - CVE-2020-14331: A buffer over write in vgacon_scroll was
    fixed (bnc#1174205).

  - CVE-2020-16166: The Linux kernel allowed remote
    attackers to make observations that help to obtain
    sensitive information about the internal state of the
    network RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and kernel/time/timer.c
    (bnc#1174757).

  - CVE-2020-10135: Legacy pairing and secure-connections
    pairing authentication in Bluetooth&reg; BR/EDR Core
    Specification v5.2 and earlier may have allowed an
    unauthenticated user to complete authentication without
    pairing credentials via adjacent access. An
    unauthenticated, adjacent attacker could impersonate a
    Bluetooth BR/EDR master or slave to pair with a
    previously paired remote device to successfully complete
    the authentication procedure without knowing the link
    key (bnc#1171988).

  - CVE-2020-0305: In cdev_get of char_dev.c, there is a
    possible use-after-free due to a race condition. This
    could lead to local escalation of privilege with System
    execution privileges needed. User interaction is not
    needed for exploitation (bnc#1174462).

  - CVE-2020-15780: An issue was discovered in
    drivers/acpi/acpi_configfs.c in the Linux kernel
    Injection of malicious ACPI tables via configfs could be
    used by attackers to bypass lockdown and secure boot
    restrictions, aka CID-75b0cea7bf30 (bnc#1173573).

  - CVE-2020-10781: zram sysfs resource consumption was
    fixed (bnc#1173074).

The following non-security bugs were fixed :

  - 9p/trans_fd: Fix concurrency del of req_list in
    p9_fd_cancelled/p9_read_work (git-fixes).

  - ACPICA: Dispatcher: add status checks (git-fixes).

  - ACPI/IORT: Fix PMCG node single ID mapping handling
    (git-fixes).

  - ACPI: video: Use native backlight on Acer Aspire 5783z
    (git-fixes).

  - ACPI: video: Use native backlight on Acer TravelMate
    5735Z (git-fixes).

  - af_key: pfkey_dump needs parameter validation
    (git-fixes).

  - agp/intel: Fix a memory leak on module initialisation
    failure (git-fixes).

  - ALSA: asihpi: delete duplicated word (git-fixes).

  - ALSA: atmel: Remove invalid 'fall through' comments
    (git-fixes).

  - ALSA: core: pcm_iec958: fix kernel-doc (git-fixes).

  - ALSA: echoaduio: Drop superfluous volatile modifier
    (git-fixes).

  - ALSA: echoaudio: Address bugs in the interrupt handling
    (git-fixes).

  - ALSA: echoaudio: Fix potential Oops in snd_echo_resume()
    (git-fixes).

  - ALSA: echoaudio: Prevent races in calls to
    set_audio_format() (git-fixes).

  - ALSA: echoaudio: Prevent some noise on unloading the
    module (git-fixes).

  - ALSA: echoaudio: Race conditions around 'opencount'
    (git-fixes).

  - ALSA: echoaudio: re-enable IRQs on failure path
    (git-fixes).

  - ALSA: echoaudio: Remove redundant check (git-fixes).

  - ALSA: firewire: fix kernel-doc (git-fixes).

  - ALSA: hda: Add support for Loongson 7A1000 controller
    (git-fixes).

  - ALSA: hda/ca0132 - Add new quirk ID for Recon3D
    (git-fixes).

  - ALSA: hda/ca0132 - Fix AE-5 microphone selection
    commands (git-fixes).

  - ALSA: hda/ca0132 - Fix ZxR Headphone gain control get
    value (git-fixes).

  - ALSA: hda: Enable sync-write operation as default for
    all controllers (git-fixes).

  - ALSA: hda: fix NULL pointer dereference during suspend
    (git-fixes).

  - ALSA: hda: fix snd_hda_codec_cleanup() documentation
    (git-fixes).

  - ALSA: hda - fix the micmute led status for Lenovo
    ThinkCentre AIO (git-fixes).

  - ALSA: hda/hdmi: Add quirk to force connectivity
    (git-fixes).

  - ALSA: hda/hdmi: Fix keep_power assignment for
    non-component devices (git-fixes).

  - ALSA: hda/hdmi: Use force connectivity quirk on another
    HP desktop (git-fixes).

  - ALSA: hda: Intel: add missing PCI IDs for ICL-H, TGL-H
    and EKL (jsc#SLE-13261).

  - ALSA: hda: Intel: add missing PCI IDs for ICL-H, TGL-H
    and EKL (jsc#SLE-13261).

  - ALSA: hda/realtek: Add alc269/alc662 pin-tables for
    Loongson-3 laptops (git-fixes).

  - ALSA: hda/realtek - change to suitable link model for
    ASUS platform (git-fixes).

  - ALSA: hda/realtek: Enable headset mic of Acer TravelMate
    B311R-31 with ALC256 (git-fixes).

  - ALSA: hda/realtek: enable headset mic of ASUS ROG
    Zephyrus G14(G401) series with ALC289 (git-fixes).

  - ALSA: hda/realtek: enable headset mic of ASUS ROG
    Zephyrus G15(GA502) series with ALC289 (git-fixes).

  - ALSA: hda/realtek - Enable Speaker for ASUS UX533 and
    UX534 (git-fixes).

  - ALSA: hda/realtek - Enable Speaker for ASUS UX563
    (git-fixes).

  - ALSA: hda/realtek: Fix add a 'ultra_low_power' function
    for intel reference board (alc256) (git-fixes).

  - ALSA: hda/realtek: Fixed ALC298 sound bug by adding
    quirk for Samsung Notebook Pen S (git-fixes).

  - ALSA: hda/realtek - Fixed HP right speaker no sound
    (git-fixes).

  - ALSA: hda/realtek: Fix pin default on Intel NUC 8 Rugged
    (git-fixes).

  - ALSA: hda/realtek - Fix unused variable warning
    (git-fixes).

  - ALSA: hda/realtek - fixup for yet another Intel
    reference board (git-fixes).

  - ALSA: hda/realtek: typo_fix: enable headset mic of ASUS
    ROG Zephyrus G14(GA401) series with ALC289 (git-fixes).

  - ALSA: hda - reverse the setting value in the
    micmute_led_set (git-fixes).

  - ALSA: hda/tegra: Disable sync-write operation
    (git-fixes).

  - ALSA: hda: Workaround for spurious wakeups on some Intel
    platforms (git-fixes).

  - ALSA: info: Drop WARN_ON() from buffer NULL sanity check
    (git-fixes).

  - ALSA: isa: delete repeated words in comments
    (git-fixes).

  - ALSA: isa/gus: remove 'set but not used' warning
    (git-fixes).

  - ALSA: isa/gus: remove -Wmissing-prototypes warnings
    (git-fixes).

  - ALSA: line6: add hw monitor volume control for POD HD500
    (git-fixes).

  - ALSA: line6: Perform sanity check for each URB creation
    (git-fixes).

  - ALSA: line6: Sync the pending work cancel at
    disconnection (git-fixes).

  - ALSA: line6: Use kmemdup in podhd_set_monitor_level()
    (git-fixes).

  - ALSA: pci/asihpi: fix kernel-doc (git-fixes).

  - ALSA: pci/asihpi: remove 'set but not used' warning
    (git-fixes).

  - ALSA: pci/asihpi: remove 'set but not used' warnings
    (git-fixes).

  - ALSA: pci/au88x0: remove 'defined but not used' warnings
    (git-fixes).

  - ALSA: pci/aw2-saa7146: remove 'set but not used' warning
    (git-fixes).

  - ALSA: pci/ctxfi/ctatc: fix kernel-doc (git-fixes).

  - ALSA: pci/ctxfi: fix kernel-doc warnings (git-fixes).

  - ALSA: pci: delete repeated words in comments
    (git-fixes).

  - ALSA: pci/echoaudio: remove 'set but not used' warning
    (git-fixes).

  - ALSA: pci/emu10k1: remove 'set but not used' warning
    (git-fixes).

  - ALSA: pci/es1938: remove 'set but not used' warning
    (git-fixes).

  - ALSA: pci/fm801: fix kernel-doc (git-fixes).

  - ALSA: pci/korg1212: remove 'set but not used' warnings
    (git-fixes).

  - ALSA: pci/oxygen/xonar_wm87x6: remove always true
    condition (git-fixes).

  - ALSA: pci/rme9652/hdspm: remove always true condition
    (git-fixes).

  - ALSA: pci/via82xx: remove 'set but not used' warnings
    (git-fixes).

  - ALSA: pcmcia/pdaudiocf: fix kernel-doc (git-fixes).

  - ALSA: seq: oss: Serialize ioctls (git-fixes).

  - ALSA: usb-audio: Add implicit feedback quirk for SSL2
    (git-fixes).

  - ALSA: usb-audio: add quirk for Pioneer DDJ-RB
    (git-fixes).

  - ALSA: usb-audio: Add registration quirk for Kingston
    HyperX Cloud Flight S (git-fixes).

  - ALSA: usb-audio: add startech usb audio dock name
    (git-fixes).

  - ALSA: usb-audio: Add support for Lenovo ThinkStation
    P620 (git-fixes).

  - ALSA: usb-audio: Creative USB X-Fi Pro SB1095 volume
    knob support (git-fixes).

  - ALSA: usb-audio: Disable Lenovo P620 Rear line-in volume
    control (git-fixes).

  - ALSA: usb-audio: endpoint : remove needless check before
    usb_free_coherent() (git-fixes).

  - ALSA: usb-audio: fix overeager device match for
    MacroSilicon MS2109 (bsc#1174625).

  - ALSA: usb-audio: Fix race against the error recovery URB
    submission (git-fixes).

  - ALSA: usb-audio: Fix some typos (git-fixes).

  - ALSA: usb-audio: fix spelling mistake 'buss' -> 'bus'
    (git-fixes).

  - ALSA: usb-audio: work around streaming quirk for
    MacroSilicon MS2109 (git-fixes).

  - ALSA: usb/line6: remove 'defined but not used' warning
    (git-fixes).

  - ALSA: vx_core: remove warning for empty loop body
    (git-fixes).

  - ALSA: xen: remove 'set but not used' warning
    (git-fixes).

  - ALSA: xen: Remove superfluous fall through comments
    (git-fixes).

  - apparmor: ensure that dfa state tables have entries
    (git-fixes).

  - apparmor: fix introspection of of task mode for
    unconfined tasks (git-fixes).

  - apparmor: Fix memory leak of profile proxy (git-fixes).

  - apparmor: Fix use-after-free in aa_audit_rule_init
    (git-fixes).

  - apparmor: remove useless aafs_create_symlink
    (git-fixes).

  - appletalk: Fix atalk_proc_init() return path
    (git-fixes).

  - arm64: armv8_deprecated: Fix undef_hook mask for thumb
    setend (bsc#1175180).

  - arm64: cacheflush: Fix KGDB trap detection
    (bsc#1175188).

  - arm64: csum: Fix handling of bad packets (bsc#1175192).

  - arm64: dts: allwinner: a64: Remove unused SPDIF sound
    card (none bsc#1175016).

  - arm64: dts: clearfog-gt-8k: set gigabit PHY reset
    deassert delay (bsc#1175347).

  - arm64: dts: exynos: Fix silent hang after boot on
    Espresso (bsc#1175346).

  - arm64: dts: imx8mm-evk: correct ldo1/ldo2 voltage range
    (none bsc#1175019).

  - arm64: dts: imx8qxp-mek: Remove unexisting Ethernet PHY
    (bsc#1175345).

  - arm64: dts: librem5-devkit: add a vbus supply to usb0
    (none bsc#1175013).

  - arm64: dts: ls1028a: delete extraneous #interrupt-cells
    for ENETC RCIE (none bsc#1175012).

  - arm64: dts: ls1043a-rdb: correct RGMII delay mode to
    rgmii-id (bsc#1174398).

  - arm64: dts: ls1046ardb: set RGMII interfaces to RGMII_ID
    mode (bsc#1174398).

  - arm64: dts: qcom: msm8998-clamshell: Fix label on l15
    regulator (git-fixes).

  - arm64: dts: rockchip: fix rk3399-puma gmac reset gpio
    (none bsc#1175021).

  - arm64: dts: rockchip: fix rk3399-puma vcc5v0-host gpio
    (none bsc#1175020).

  - arm64: dts: rockchip: Rename dwc3 device nodes on rk3399
    to make dtc happy (none bsc#1175015).

  - arm64: dts: rockchip: Replace RK805 PMIC node name with
    'pmic' on rk3328 boards (none bsc#1175014).

  - arm64: dts: uDPU: fix broken ethernet (bsc#1175344).

  - arm64: dts: uniphier: Set SCSSI clock and reset IDs for
    each channel (none bsc#1175011).

  - arm64: errata: use arm_smccc_1_1_get_conduit()
    (bsc#1174906).

  - arm64: Fix PTRACE_SYSEMU semantics (bsc#1175185).

  - arm64: fix the flush_icache_range arguments in
    machine_kexec (bsc#1175184).

  - arm64: hugetlb: avoid potential NULL dereference
    (bsc#1175183).

  - arm64: hw_breakpoint: Do not invoke overflow handler on
    uaccess watchpoints (bsc#1175189).

  - arm64: insn: Fix two bugs in encoding 32-bit logical
    immediates (bsc#1175186).

  - arm64: kexec_file: print appropriate variable
    (bsc#1175187).

  - arm64: kgdb: Fix single-step exception handling oops
    (bsc#1175191).

  - arm64: Retrieve stolen time as paravirtualized guest
    (bsc#1172197 jsc#SLE-13593).

  - arm64: Retrieve stolen time as paravirtualized guest
    (bsc#1172197 jsc#SLE-13593).

  - arm64: tegra: Enable I2C controller for EEPROM (none
    bsc#1175010).

  - arm64: tegra: Fix ethernet phy-mode for Jetson Xavier
    (none bsc#1175017).

  - arm64: tegra: Fix flag for 64-bit resources in 'ranges'
    property (none bsc#1175018).

  - arm64: tegra: Fix Tegra194 PCIe compatible string (none
    bsc#1175009).

  - arm64: vdso: Add -fasynchronous-unwind-tables to cflags
    (bsc#1175182).

  - arm64: vdso: do not free unallocated pages
    (bsc#1175181).

  - arm/arm64: Make use of the SMCCC 1.1 wrapper
    (bsc#1174906).

  - arm/arm64: Provide a wrapper for SMCCC 1.1 calls
    (bsc#1174906).

  - arm/arm64: smccc/psci: add arm_smccc_1_1_get_conduit()
    (bsc#1174906).

  - ARM: percpu.h: fix build error (git-fixes).

  - arm: spectre-v2: use arm_smccc_1_1_get_conduit()
    (bsc#1174906).

  - ASoC: codecs: max98373: Removed superfluous volume
    control from chip default (git-fixes).

  - ASoc: codecs: max98373: remove Idle_bias_on to let codec
    suspend (git-fixes).

  - ASoC: fsl_sai: Fix value of FSL_SAI_CR1_RFW_MASK
    (git-fixes).

  - ASoC: hdac_hda: fix deadlock after PCM open error
    (git-fixes).

  - ASoC: Intel: bxt_rt298: add missing .owner field
    (git-fixes).

  - ASoC: Intel: bytcht_es8316: Add missed put_device()
    (git-fixes).

  - ASoC: meson: axg-tdmin: fix g12a skew (git-fixes).

  - ASoC: meson: axg-tdm-interface: fix link fmt setup
    (git-fixes).

  - ASoC: meson: fixes the missed kfree() for
    axg_card_add_tdm_loopback (git-fixes).

  - ASoC: rockchip: add format and rate constraints on
    rk3399 (git-fixes).

  - ASoC: rt286: fix unexpected interrupt happens
    (git-fixes).

  - ASoC: rt5670: Add new gpio1_is_ext_spk_en quirk and
    enable it on the Lenovo Miix 2 10 (git-fixes).

  - ASoC: rt5670: Correct RT5670_LDO_SEL_MASK (git-fixes).

  - ASoC: rt5670: Fix dac- and adc- vol-tlv values being off
    by a factor of 10 (git-fixes).

  - ASoC: rt5682: Report the button event in the headset
    type only (git-fixes).

  - ASoC: SOF: nocodec: add missing .owner field
    (git-fixes).

  - ASoC: topology: fix kernel oops on route addition error
    (git-fixes).

  - ASoC: topology: fix tlvs in error handling for
    widget_dmixer (git-fixes).

  - ASoC: wm8974: fix Boost Mixer Aux Switch (git-fixes).

  - ASoC: wm8974: remove unsupported clock mode (git-fixes).

  - ath10k: Acquire tx_lock in tx error paths (git-fixes).

  - ath10k: enable transmit data ack RSSI for QCA9884
    (git-fixes).

  - ath9k: Fix general protection fault in
    ath9k_hif_usb_rx_cb (git-fixes).

  - ath9k: Fix regression with Atheros 9271 (git-fixes).

  - atm: fix atm_dev refcnt leaks in
    atmtcp_remove_persistent (git-fixes).

  - AX.25: Fix out-of-bounds read in ax25_connect()
    (git-fixes).

  - AX.25: Prevent integer overflows in connect and sendmsg
    (git-fixes).

  - AX.25: Prevent out-of-bounds read in ax25_sendmsg()
    (git-fixes).

  - ax88172a: fix ax88172a_unbind() failures (git-fixes).

  - b43: Remove uninitialized_var() usage (git-fixes).

  - blk-mq: consider non-idle request as 'inflight' in
    blk_mq_rq_inflight() (bsc#1165933).

  - Bluetooth: btmtksdio: fix up firmware download sequence
    (git-fixes).

  - Bluetooth: btusb: fix up firmware download sequence
    (git-fixes).

  - Bluetooth: fix kernel oops in store_pending_adv_report
    (git-fixes).

  - Bluetooth: Fix slab-out-of-bounds read in
    hci_extended_inquiry_result_evt() (git-fixes).

  - Bluetooth: Fix update of connection state in
    `hci_encrypt_cfm` (git-fixes).

  - Bluetooth: hci_h5: Set HCI_UART_RESET_ON_INIT to correct
    flags (git-fixes).

  - Bluetooth: hci_serdev: Only unregister device if it was
    registered (git-fixes).

  - Bluetooth: Prevent out-of-bounds read in
    hci_inquiry_result_evt() (git-fixes).

  - Bluetooth: Prevent out-of-bounds read in
    hci_inquiry_result_with_rssi_evt() (git-fixes).

  - bnxt_en: Init ethtool link settings after reading
    updated PHY configuration (jsc#SLE-8371 bsc#1153274).

  - bnxt_en: Init ethtool link settings after reading
    updated PHY configuration (jsc#SLE-8371 bsc#1153274).

  - bpf: Do not allow btf_ctx_access with __int128 types
    (bsc#1155518).

  - bpf: Fix map leak in HASH_OF_MAPS map (bsc#1155518).

  - bpfilter: fix up a sparse annotation (bsc#1155518).

  - bpfilter: Initialize pos variable (bsc#1155518).

  - bpfilter: reject kernel addresses (bsc#1155518).

  - bpfilter: switch to kernel_write (bsc#1155518).

  - bpf: net: Avoid copying sk_user_data of reuseport_array
    during sk_clone (bsc#1155518).

  - bpf: net: Avoid incorrect bpf_sk_reuseport_detach call
    (bsc#1155518).

  - brcmfmac: Set timeout value when configuring power save
    (bsc#1173468).

  - brcmfmac: Transform compatible string for FW loading
    (bsc#1169771).

  - bridge: Avoid infinite loop when suppressing NS messages
    with invalid options (networking-stable-20_06_10).

  - bridge: mcast: Fix MLD2 Report IPv6 payload length check
    (git-fixes).

  - btmrvl: Fix firmware filename for sd8977 chipset
    (git-fixes).

  - btmrvl: Fix firmware filename for sd8997 chipset
    (git-fixes).

  - btrfs: add assertions for tree == inode->io_tree to
    extent IO helpers (bsc#1174438).

  - btrfs: avoid unnecessary splits when setting bits on an
    extent io tree (bsc#1175377).

  - btrfs: change timing for qgroup reserved space for
    ordered extents to fix reserved space leak
    (bsc#1172247).

  - btrfs: delete the ordered isize update code
    (bsc#1175377).

  - btrfs: do not set path->leave_spinning for truncate
    (bsc#1175377).

  - btrfs: drop argument tree from
    btrfs_lock_and_flush_ordered_range (bsc#1174438).

  - btrfs: file: reserve qgroup space after the hole punch
    range is locked (bsc#1172247).

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

  - btrfs: fix deadlock during fast fsync when logging
    prealloc extents beyond eof (bsc#1175377).

  - btrfs: fix double free on ulist after backref resolution
    failure (bsc#1175149).

  - btrfs: fix failure of RWF_NOWAIT write into prealloc
    extent beyond eof (bsc#1174438).

  - btrfs: fix fatal extent_buffer readahead vs releasepage
    race (bsc#1175149).

  - btrfs: fix hang on snapshot creation after RWF_NOWAIT
    write (bsc#1174438).

  - btrfs: fix lost i_size update after cloning inline
    extent (bsc#1175377).

  - btrfs: fix page leaks after failure to lock page for
    delalloc (bsc#1175149).

  - btrfs: fix race between block group removal and block
    group creation (bsc#1175149).

  - btrfs: fix race between shrinking truncate and fiemap
    (bsc#1175377).

  - btrfs: fix RWF_NOWAIT write not failling when we need to
    cow (bsc#1174438).

  - btrfs: fix RWF_NOWAIT writes blocking on extent locks
    and waiting for IO (bsc#1174438).

  - btrfs: fix space_info bytes_may_use underflow after
    nocow buffered write (bsc#1175149).

  - btrfs: fix space_info bytes_may_use underflow during
    space cache writeout (bsc#1175149).

  - btrfs: fix wrong file range cleanup after an error
    filling dealloc range (bsc#1175149).

  - btrfs: inode: fix NULL pointer dereference if inode does
    not need compression (bsc#1174484).

  - btrfs: inode: move qgroup reserved space release to the
    callers of insert_reserved_file_extent() (bsc#1172247).

  - btrfs: inode: refactor the parameters of
    insert_reserved_file_extent() (bsc#1172247).

  - btrfs: introduce per-inode file extent tree
    (bsc#1175377).

  - btrfs: make btrfs_ordered_extent naming consistent with
    btrfs_file_extent_item (bsc#1172247).

  - btrfs: move extent_io_tree defs to their own header
    (bsc#1175377).

  - btrfs: Move free_pages_out label in inline extent
    handling branch in compress_file_range (bsc#1175263).

  - btrfs: qgroup: allow to unreserve range without
    releasing other ranges (bsc#1120163).

  - btrfs: qgroup: fix data leak caused by race between
    writeback and truncate (bsc#1172247).

  - btrfs: qgroup: remove ASYNC_COMMIT mechanism in favor of
    reserve retry-after-EDQUOT (bsc#1120163).

  - btrfs: qgroup: try to flush qgroup space when we get
    -EDQUOT (bsc#1120163).

  - btrfs: Remove delalloc_end argument from
    extent_clear_unlock_delalloc (bsc#1175149).

  - btrfs: Remove leftover of in-band dedupe (bsc#1175149).

  - btrfs: remove unnecessary delalloc mutex for inodes
    (bsc#1175377).

  - btrfs: Rename btrfs_join_transaction_nolock
    (bsc#1175377).

  - btrfs: replace all uses of btrfs_ordered_update_i_size
    (bsc#1175377).

  - btrfs: separate out the extent io init function
    (bsc#1175377).

  - btrfs: separate out the extent leak code (bsc#1175377).

  - btrfs: trim: fix underflow in trim length to prevent
    access beyond device boundary (bsc#1175263).

  - btrfs: use btrfs_ordered_update_i_size in
    clone_finish_inode_update (bsc#1175377).

  - btrfs: use correct count in btrfs_file_write_iter()
    (bsc#1174438).

  - btrfs: use the file extent tree infrastructure
    (bsc#1175377).

  - bus: ti-sysc: Do not disable on suspend for no-idle
    (git-fixes).

  - cfg80211: check vendor command doit pointer before use
    (git-fixes).

  - clk: actions: Fix h_clk for Actions S500 SoC
    (git-fixes).

  - clk: at91: clk-generated: check best_rate against ranges
    (git-fixes).

  - clk: at91: clk-generated: continue if
    __clk_determine_rate() returns error (git-fixes).

  - clk: at91: sam9x60: fix main rc oscillator frequency
    (git-fixes).

  - clk: at91: sam9x60-pll: check fcore against ranges
    (git-fixes).

  - clk: at91: sam9x60-pll: use logical or for range check
    (git-fixes).

  - clk: at91: sckc: register slow_rc with accuracy option
    (git-fixes).

  - clk: bcm2835: Do not use prediv with bcm2711's PLLs
    (bsc#1174865).

  - clk: bcm63xx-gate: fix last clock availability
    (git-fixes).

  - clk: clk-atlas6: fix return value check in
    atlas6_clk_init() (git-fixes).

  - clk: iproc: round clock rate to the closest (git-fixes).

  - clk: qcom: gcc-sdm660: Add missing modem reset
    (git-fixes).

  - clk: qcom: gcc-sdm660: Fix up gcc_mss_mnoc_bimc_axi_clk
    (git-fixes).

  - clk: rockchip: Revert 'fix wrong mmc sample phase shift
    for rk3328' (git-fixes).

  - clk: scmi: Fix min and max rate when registering clocks
    with discrete rates (git-fixes).

  - clk: spear: Remove uninitialized_var() usage
    (git-fixes).

  - clk: st: Remove uninitialized_var() usage (git-fixes).

  - console: newport_con: fix an issue about leak related
    system resources (git-fixes).

  - crc-t10dif: Fix potential crypto notify dead-lock
    (git-fixes).

  - crypto: caam - Fix argument type in
    handle_imx6_err005766 (git-fixes).

  - crypto: ccp - Fix use of merged scatterlists
    (git-fixes).

  - crypto: ccree - fix resource leak on error path
    (git-fixes).

  - crypto: cpt - do not sleep of CRYPTO_TFM_REQ_MAY_SLEEP
    was not specified (git-fixes).

  - crypto: hisilicon - do not sleep of
    CRYPTO_TFM_REQ_MAY_SLEEP was not specified (git-fixes).

  - crypto: qat - fix double free in
    qat_uclo_create_batch_init_list (git-fixes).

  - dccp: Fix possible memleak in dccp_init and dccp_fini
    (networking-stable-20_06_16).

  - Delete
    patches.suse/apparmor-Fix-memory-leak-of-profile-proxy.p
    atch (bsc#1174627)

  - devinet: fix memleak in inetdev_init()
    (networking-stable-20_06_07).

  - devlink: ignore -EOPNOTSUPP errors on dumpit
    (bsc#1154353).

  - /dev/mem: Add missing memory barriers for devmem_inode
    (git-fixes).

  - /dev/mem: Revoke mappings when a driver claims the
    region (git-fixes).

  - devres: keep both device name and resource name in
    pretty name (git-fixes).

  - dlm: remove BUG() before panic() (git-fixes).

  - dmaengine: dmatest: stop completed threads when running
    without set channel (git-fixes).

  - dmaengine: dw: Initialize channel before each transfer
    (git-fixes).

  - dmaengine: fsl-edma-common: correct DSIZE_32BYTE
    (git-fixes).

  - dmaengine: fsl-edma: Fix NULL pointer exception in
    fsl_edma_tx_handler (git-fixes).

  - dmaengine: fsl-edma: fix wrong tcd endianness for
    big-endian cpu (git-fixes).

  - dmaengine: imx-sdma: Fix: Remove 'always true'
    comparison (git-fixes).

  - dmaengine: ioat setting ioat timeout as module parameter
    (git-fixes).

  - dmaengine: mcf-edma: Fix NULL pointer exception in
    mcf_edma_tx_handler (git-fixes).

  - dmaengine: sh: usb-dmac: set tx_result parameters
    (git-fixes).

  - dmaengine: tegra210-adma: Fix runtime PM imbalance on
    error (git-fixes).

  - dm: do not use waitqueue for request-based DM
    (bsc#1165933).

  - docs: fix memory.low description in cgroup-v2.rst
    (git-fixes). (SLE documentation might refer to
    cgroup-v2.rst.)

  - dpaa_eth: FMan erratum A050385 workaround (bsc#1174396).

  - dpaa_eth: Make dpaa_a050385_wa static (bsc#1174396).

  - drbd: Remove uninitialized_var() usage (git-fixes).

  - driver core: Avoid binding drivers to dead devices
    (git-fixes).

  - drivers/firmware/psci: Fix memory leakage in
    alloc_init_cpu_groups() (git-fixes).

  - drivers/net/wan: lapb: Corrected the usage of skb_cow
    (git-fixes).

  - drm/amd/display: Clear dm_state for fast updates
    (git-fixes).

  - drm/amd/display: Use kfree() to free rgb_user in
    calculate_user_regamma_ramp() (git-fixes).

  - drm/amdgpu/atomfirmware: fix vram_info fetching for
    renoir (git-fixes).

  - drm/amdgpu/display: use blanked rather than plane state
    for sync (bsc#1152489) &#9;* refreshed for context
    changes &#9;* protect code with CONFIG_DRM_AMD_DC_DCN2_0

  - drm/amdgpu: do not do soft recovery if gpu_recovery=0
    (git-fixes).

  - drm/amdgpu: Fix NULL dereference in dpm sysfs handlers
    (git-fixes).

  - drm/amdgpu: fix preemption unit test (git-fixes).

  - drm/amdgpu/gfx10: fix race condition for kiq
    (git-fixes).

  - drm/amdgpu: Prevent kernel-infoleak in
    amdgpu_info_ioctl() (git-fixes).

  - drm/amdgpu/sdma5: fix wptr overwritten in ->get_wptr()
    (git-fixes).

  - drm/amdgpu: use %u rather than %d for sclk/mclk
    (git-fixes).

  - drm/amd/powerplay: fix a crash when overclocking Vega M
    (bsc#1152472)

  - drm/amd/powerplay: fix a crash when overclocking Vega M
    (git-fixes).

  - drm/arm: fix unintentional integer overflow on left
    shift (git-fixes).

  - drm/bridge: dw-hdmi: Do not cleanup i2c adapter and ddc
    ptr in (bsc#1152472) &#9;* refreshed for context changes

  - drm/bridge: sil_sii8620: initialize return of
    sii8620_readb (git-fixes).

  - drm/bridge: ti-sn65dsi86: Clear old error bits before
    AUX transfers (git-fixes).

  - drm/bridge: ti-sn65dsi86: Do not use kernel-doc comment
    for local array (git-fixes).

  - drm/bridge: ti-sn65dsi86: Fix off-by-one error in clock
    choice (bsc#1152489) &#9;* refreshed for context changes

  - drm/dbi: Fix SPI Type 1 (9-bit) transfer (bsc#1152472)
    &#9;* move drm_mipi_dbi.c -> tinydrm/mipi-dbi.c

  - drm/etnaviv: Fix error path on failure to enable bus clk
    (git-fixes).

  - drm/exynos: fix ref count leak in mic_pre_enable
    (git-fixes).

  - drm/exynos: Properly propagate return value in
    drm_iommu_attach_device() (git-fixes).

  - drm: fix drm_dp_mst_port refcount leaks in
    drm_dp_mst_allocate_vcpi (git-fixes).

  - drm/gem: Fix a leak in drm_gem_objects_lookup()
    (git-fixes).

  - drm: hold gem reference until object is no longer
    accessed (git-fixes).

  - drm/i915: Actually emit the await_start (bsc#1174737).

  - drm/i915: Copy across scheduler behaviour flags across
    submit fences (bsc#1174737).

  - drm/i915: Do not poison i915_request.link on removal
    (bsc#1174737).

  - drm/i915: Drop no-semaphore boosting (bsc#1174737).

  - drm/i915: Eliminate the trylock for awaiting an earlier
    request (bsc#1174737).

  - drm/i915/fbc: Fix fence_y_offset handling (bsc#1152489)
    &#9;* context changes

  - drm/i915: Flush execution tasklets before checking
    request status (bsc#1174737).

  - drm/i915: Flush tasklet submission before sleeping on
    i915_request_wait (bsc#1174737).

  - drm/i915/gt: Close race between engine_park and
    intel_gt_retire_requests (git-fixes).

  - drm/i915/gt: Flush submission tasklet before
    waiting/retiring (bsc#1174737).

  - drm/i915/gt: Ignore irq enabling on the virtual engines
    (git-fixes).

  - drm/i915/gt: Move new timelines to the end of
    active_list (git-fixes).

  - drm/i915/gt: Only swap to a random sibling once upon
    creation (bsc#1152489) &#9;* context changes

  - drm/i915/gt: Unlock engine-pm after queuing the kernel
    context switch (git-fixes).

  - drm/i915: Ignore submit-fences on the same timeline
    (bsc#1174737).

  - drm/i915: Improve the start alignment of bonded pairs
    (bsc#1174737).

  - drm/i915: Keep track of request among the scheduling
    lists (bsc#1174737).

  - drm/i915: Lock signaler timeline while navigating
    (bsc#1174737).

  - drm/i915: Mark i915_request.timeline as a volatile, rcu
    pointer (bsc#1174737).

  - drm/i915: Mark racy read of intel_engine_cs.saturated
    (bsc#1174737).

  - drm/i915: Mark up unlocked update of
    i915_request.hwsp_seqno (bsc#1174737).

  - drm/i915: Move cec_notifier to
    intel_hdmi_connector_unregister, v2. (bsc#1152489) &#9;*
    context changes

  - drm/i915: Peel dma-fence-chains for await (bsc#1174737).

  - drm/i915: Prevent using semaphores to chain up to
    external fences (bsc#1174737).

  - drm/i915: Protect i915_request_await_start from early
    waits (bsc#1174737).

  - drm/i915: Pull waiting on an external dma-fence into its
    routine (bsc#1174737).

  - drm/i915: Rely on direct submission to the queue
    (bsc#1174737).

  - drm/i915: Remove wait priority boosting (bsc#1174737).

  - drm/i915: Reorder await_execution before await_request
    (bsc#1174737).

  - drm/i915: Return early for await_start on same timeline
    (bsc#1174737).

  - drm/i915: Use EAGAIN for trylock failures (bsc#1174737).

  - drm/imx: fix use after free (git-fixes).

  - drm/imx: imx-ldb: Disable both channels for split mode
    in enc->disable() (git-fixes).

  - drm/imx: tve: fix regulator_disable error path
    (git-fixes).

  - drm/ingenic: Fix incorrect assumption about plane->index
    (bsc#1152489) &#9;* refreshed for context changes

  - drm: mcde: Fix display initialization problem
    (git-fixes).

  - drm/mediatek: Check plane visibility in atomic_update
    (git-fixes).

  - drm/mipi: use dcs write for
    mipi_dsi_dcs_set_tear_scanline (git-fixes).

  - drm/msm/dpu: allow initialization of encoder locks
    during encoder init (git-fixes).

  - drm/msm: fix potential memleak in error branch
    (git-fixes).

  - drm/nouveau/fbcon: fix module unload when fbcon init has
    failed for some reason (git-fixes).

  - drm/nouveau/fbcon: zero-initialise the mode_cmd2
    structure (git-fixes).

  - drm/nouveau/i2c/g94-: increase
    NV_PMGR_DP_AUXCTL_TRANSACTREQ timeout (git-fixes).

  - drm: panel-orientation-quirks: Add quirk for Asus T101HA
    panel (git-fixes).

  - drm: panel-orientation-quirks: Use generic
    orientation-data for Acer S1003 (git-fixes).

  - drm/panel: otm8009a: Drop unnessary
    backlight_device_unregister() (git-fixes).

  - drm: panel: simple: Fix bpc for LG LB070WV8 panel
    (git-fixes).

  - drm/radeon: fix array out-of-bounds read and write
    issues (git-fixes).

  - drm/radeon: fix double free (git-fixes).

  - drm/stm: repair runtime power management (git-fixes).

  - drm: sun4i: hdmi: Fix inverted HPD result (git-fixes).

  - drm/sun4i: tcon: Separate quirks for tcon0 and tcon1 on
    A20 (git-fixes).

  - drm/tegra: hub: Do not enable orphaned window group
    (git-fixes).

  - drm/vgem: Replace opencoded version of
    drm_gem_dumb_map_offset() (bsc#1152489) &#9;* refreshed
    for context changes

  - drm/vmwgfx: Fix two list_for_each loop exit tests
    (git-fixes).

  - drm/vmwgfx: Use correct vmw_legacy_display_unit pointer
    (git-fixes).

  - exfat: add missing brelse() calls on error paths
    (git-fixes).

  - exfat: fix incorrect update of stream entry in
    __exfat_truncate() (git-fixes).

  - exfat: fix memory leak in exfat_parse_param()
    (git-fixes).

  - exfat: move setting VOL_DIRTY over
    exfat_remove_entries() (git-fixes).

  - fbdev: Detect integer underflow at 'struct
    fbcon_ops'->clear_margins (git-fixes).

  - firmware: arm_scmi: Fix SCMI genpd domain probing
    (git-fixes).

  - firmware: arm_scmi: Keep the discrete clock rates sorted
    (git-fixes).

  - firmware: arm_sdei: use common SMCCC_CONDUIT_*
    (bsc#1174906).

  - firmware: Fix a reference count leak (git-fixes).

  - firmware_loader: fix memory leak for paged buffer
    (bsc#1175367).

  - firmware/psci: use common SMCCC_CONDUIT_* (bsc#1174906).

  - firmware: smccc: Add ARCH_SOC_ID support (bsc#1174906).

  - firmware: smccc: Add function to fetch SMCCC version
    (bsc#1174906).

  - firmware: smccc: Add HAVE_ARM_SMCCC_DISCOVERY to
    identify SMCCC v1.1 and above (bsc#1174906).

  - firmware: smccc: Add the definition for SMCCCv1.2
    version/error codes (bsc#1174906).

  - firmware: smccc: Drop smccc_version enum and use
    ARM_SMCCC_VERSION_1_x instead (bsc#1174906).

  - firmware: smccc: Refactor SMCCC specific bits into
    separate file (bsc#1174906).

  - firmware: smccc: Update link to latest SMCCC
    specification (bsc#1174906).

  - fpga: dfl: fix bug in port reset handshake (git-fixes).

  - fsl/fman: detect FMan erratum A050385 (bsc#1174396)
    Update arm64 config file

  - fuse: copy_file_range should truncate cache (git-fixes).

  - fuse: fix copy_file_range cache issues (git-fixes).

  - fuse: Fix parameter for FS_IOC_(GET,SET)FLAGS
    (bsc#1175176).

  - fuse: fix weird page warning (bsc#1175175).

  - geneve: fix an uninitialized value in
    geneve_changelink() (git-fixes).

  - genirq/affinity: Improve __irq_build_affinity_masks()
    (bsc#1174897 ltc#187090).

  - genirq/affinity: Remove const qualifier from
    node_to_cpumask argument (bsc#1174897 ltc#187090).

  - genirq/affinity: Spread vectors on node according to
    nr_cpu ratio (bsc#1174897 ltc#187090).

  - gfs2: Another gfs2_find_jhead fix (bsc#1174824).

  - gfs2: fix gfs2_find_jhead that returns uninitialized
    jhead with seq 0 (bsc#1174825).

  - go7007: add sanity checking for endpoints (git-fixes).

  - gpio: arizona: handle pm_runtime_get_sync failure case
    (git-fixes).

  - gpio: arizona: put pm_runtime in case of failure
    (git-fixes).

  - gpio: max77620: Fix missing release of interrupt
    (git-fixes).

  - gpio: pca953x: disable regmap locking for automatic
    address incrementing (git-fixes).

  - gpio: pca953x: Fix GPIO resource leak on Intel Galileo
    Gen 2 (git-fixes).

  - gpio: pca953x: Override IRQ for one of the expanders on
    Galileo Gen 2 (git-fixes).

  - gpu: host1x: Detach driver on unregister (git-fixes).

  - habanalabs: increase timeout during reset (git-fixes).

  - HID: alps: support devices with report id 2 (git-fixes).

  - HID: apple: Disable Fn-key key-re-mapping on clone
    keyboards (git-fixes).

  - HID: i2c-hid: add Mediacom FlexBook edge13 to descriptor
    override (git-fixes).

  - HID: logitech-hidpp: avoid repeated 'multiplier = ' log
    messages (git-fixes).

  - HID: magicmouse: do not set up autorepeat (git-fixes).

  - HID: quirks: Always poll Obins Anne Pro 2 keyboard
    (git-fixes).

  - HID: quirks: Ignore Simply Automated UPB PIM
    (git-fixes).

  - HID: quirks: Remove ITE 8595 entry from
    hid_have_special_driver (git-fixes).

  - HID: steam: fixes race in handling device list
    (git-fixes).

  - hippi: Fix a size used in a 'pci_free_consistent()' in
    an error handling path (git-fixes).

  - hwmon: (adm1275) Make sure we are reading enough data
    for different chips (git-fixes).

  - hwmon: (aspeed-pwm-tacho) Avoid possible buffer overflow
    (git-fixes).

  - hwmon: (emc2103) fix unable to change fan pwm1_enable
    attribute (git-fixes).

  - hwmon: (nct6775) Accept PECI Calibration as temperature
    source for NCT6798D (git-fixes).

  - hwmon: (scmi) Fix potential buffer overflow in
    scmi_hwmon_probe() (git-fixes).

  - hwrng: ks-sa - Fix runtime PM imbalance on error
    (git-fixes).

  - i2c: also convert placeholder function to return errno
    (git-fixes).

  - i2c: eg20t: Load module automatically if ID matches
    (git-fixes).

  - i2c: i2c-qcom-geni: Fix DMA transfer race (git-fixes).

  - i2c: iproc: fix race between client unreg and isr
    (git-fixes).

  - i2c: rcar: always clear ICSAR to avoid side effects
    (git-fixes).

  - i2c: rcar: avoid race when unregistering slave
    (git-fixes).

  - i2c: rcar: slave: only send STOP event when we have been
    addressed (git-fixes).

  - i2c: slave: add sanity check when unregistering
    (git-fixes).

  - i2c: slave: improve sanity check when registering
    (git-fixes).

  - i40iw: Do an RCU lookup in i40iw_add_ipv4_addr
    (git-fixes).

  - i40iw: Fix error handling in i40iw_manage_arp_cache()
    (git-fixes).

  - i40iw: fix NULL pointer dereference on a null wqe
    pointer (git-fixes).

  - i40iw: Report correct firmware version (git-fixes).

  - IB/cma: Fix ports memory leak in cma_configfs
    (git-fixes).

  - IB/core: Fix potential NULL pointer dereference in pkey
    cache (git-fixes).

  - IB/hfi1: Do not destroy hfi1_wq when the device is shut
    down (bsc#1174409).

  - IB/hfi1: Do not destroy link_wq when the device is shut
    down (bsc#1174409).

  - IB/hfi1: Ensure pq is not left on waitlist (git-fixes).

  - IB/hfi1: Fix another case where pq is left on waitlist
    (bsc#1174411).

  - IB/hfi1: Fix memory leaks in sysfs registration and
    unregistration (git-fixes).

  - IB/hfi1: Fix module use count flaw due to leftover
    module put calls (bsc#1174407).

  - IB/hfi1, qib: Ensure RCU is locked when accessing list
    (git-fixes).

  - IB/ipoib: Fix double free of skb in case of multicast
    traffic in CM mode (git-fixes).

  - IB/mad: Fix use after free when destroying MAD agent
    (git-fixes).

  - IB/mlx4: Test return value of calls to
    ib_get_cached_pkey (git-fixes).

  - IB/mlx5: Fix 50G per lane indication (git-fixes).

  - IB/mlx5: Fix DEVX support for MLX5_CMD_OP_INIT2INIT_QP
    command (git-fixes).

  - IB/mlx5: Fix missing congestion control debugfs on rep
    rdma device (git-fixes).

  - IB/mlx5: Replace tunnel mpls capability bits for
    tunnel_offloads (git-fixes).

  - ibmvnic: Fix IRQ mapping disposal in error path
    (bsc#1175112 ltc#187459).

  - IB/qib: Call kobject_put() when kobject_init_and_add()
    fails (git-fixes).

  - IB/rdmavt: Always return ERR_PTR from
    rvt_create_mmap_info() (git-fixes).

  - IB/rdmavt: Delete unused routine (git-fixes).

  - IB/rdmavt: Fix RQ counting issues causing use of an
    invalid RWQE (bsc#1174770).

  - IB/sa: Resolv use-after-free in ib_nl_make_request()
    (git-fixes).

  - ide: Remove uninitialized_var() usage (git-fixes).

  - ieee802154: fix one possible memleak in adf7242_probe
    (git-fixes).

  - iio: adc: ad7780: Fix a resource handling path in
    'ad7780_probe()' (git-fixes).

  - iio: core: add missing IIO_MOD_H2/ETHANOL string
    identifiers (git-fixes).

  - iio:health:afe4404 Fix timestamp alignment and prevent
    data leak (git-fixes).

  - iio:humidity:hdc100x Fix alignment and data leak issues
    (git-fixes).

  - iio:humidity:hts221 Fix alignment and data leak issues
    (git-fixes).

  - iio: improve IIO_CONCENTRATION channel type description
    (git-fixes).

  - iio:magnetometer:ak8974: Fix alignment and data leak
    issues (git-fixes).

  - iio: magnetometer: ak8974: Fix runtime PM imbalance on
    error (git-fixes).

  - iio: mma8452: Add missed iio_device_unregister() call in
    mma8452_probe() (git-fixes).

  - iio:pressure:ms5611 Fix buffer element alignment
    (git-fixes).

  - iio: pressure: zpa2326: handle pm_runtime_get_sync
    failure (git-fixes).

  - Input: elan_i2c - add more hardware ID for Lenovo
    laptops (git-fixes).

  - Input: elan_i2c - only increment wakeup count on touch
    (git-fixes).

  - Input: goodix - fix touch coordinates on Cube I15-TC
    (git-fixes).

  - Input: i8042 - add Lenovo XiaoXin Air 12 to i8042 nomux
    list (git-fixes).

  - Input: mms114 - add extra compatible for mms345l
    (git-fixes).

  - Input: sentelic - fix error return when fsp_reg_write
    fails (git-fixes).

  - Input: synaptics - enable InterTouch for ThinkPad X1E
    1st gen (git-fixes).

  - integrity: remove redundant initialization of variable
    ret (git-fixes).

  - intel_th: Fix a NULL dereference when hub driver is not
    loaded (git-fixes).

  - intel_th: pci: Add Emmitsburg PCH support (git-fixes).

  - intel_th: pci: Add Jasper Lake CPU support (git-fixes).

  - intel_th: pci: Add Tiger Lake PCH-H support (git-fixes).

  - io-mapping: indicate mapping failure (git-fixes).

  - iommu/arm-smmu-v3: Do not reserve implementation defined
    register space (bsc#1174126).

  - iommu/vt-d: Enable PCI ACS for platform opt in hint
    (bsc#1174127).

  - iommu/vt-d: Update scalable mode paging structure
    coherency (bsc#1174128).

  - ionic: centralize queue reset code (bsc#1167773).

  - ionic: fix up filter locks and debug msgs (bsc#1167773).

  - ionic: keep rss hash after fw update (bsc#1167773).

  - ionic: unlock queue mutex in error path (bsc#1167773).

  - ionic: update filter id after replay (bsc#1167773).

  - ionic: update the queue count on open (bsc#1167773).

  - ionic: use mutex to protect queue operations
    (bsc#1167773).

  - ionic: use offset for ethtool regs data (bsc#1167773).

  - irqchip/gic: Atomically update affinity (bsc#1175195).

  - kabi fix for
    SUNRPC-dont-update-timeout-value-on-connection-reset.pat
    ch (bsc1174263).

  - kABI: reintroduce inet_hashtables.h include to l2tp_ip
    (kabi).

  - kABI: restore signature of xfrm_policy_bysel_ctx() and
    xfrm_policy_byid() (bsc#1174645).

  - kABI workaround for enum cpuhp_state (git-fixes).

  - kABI workaround for struct kvm_device (git-fixes). Just
    change an variable to 'const' type in kvm_device.

  - kABI workaround for struct kvm_vcpu_arch (git-fixes).

  - kernel.h: remove duplicate include of asm/div64.h
    (git-fixes).

  - keys: asymmetric: fix error return code in
    software_key_query() (git-fixes).

  - kobject: Avoid premature parent object freeing in
    kobject_cleanup() (git-fixes).

  - KVM: Allow kvm_device_ops to be const (bsc#1172197
    jsc#SLE-13593).

  - KVM: Allow kvm_device_ops to be const (bsc#1172197
    jsc#SLE-13593).

  - KVM: arm64: Annotate hyp NMI-related functions as
    __always_inline (bsc#1175190).

  - KVM: arm64: Correct PSTATE on exception entry
    (bsc#1133021).

  - KVM: arm64: Document PV-time interface (bsc#1172197
    jsc#SLE-13593).

  - KVM: arm64: Document PV-time interface (bsc#1172197
    jsc#SLE-13593).

  - KVM: arm64: Fix 32bit PC wrap-around (bsc#1133021).

  - KVM: arm64: Implement PV_TIME_FEATURES call (bsc#1172197
    jsc#SLE-13593).

  - KVM: arm64: Implement PV_TIME_FEATURES call (bsc#1172197
    jsc#SLE-13593).

  - KVM: arm64: Make vcpu_cp1x() work on Big Endian hosts
    (bsc#1133021).

  - KVM: arm64: Provide VCPU attributes for stolen time
    (bsc#1172197 jsc#SLE-13593).

  - KVM: arm64: Provide VCPU attributes for stolen time
    (bsc#1172197 jsc#SLE-13593).

  - KVM: arm64: Select TASK_DELAY_ACCT+TASKSTATS rather than
    SCHEDSTATS (bsc#1172197 jsc#SLE-13593).

  - KVM: arm64: Select TASK_DELAY_ACCT+TASKSTATS rather than
    SCHEDSTATS (bsc#1172197 jsc#SLE-13593).

  - KVM: arm64: Stop writing aarch32's CSSELR into ACTLR
    (bsc#1133021).

  - KVM: arm64: Support stolen time reporting via shared
    structure (bsc#1172197 jsc#SLE-13593).

  - KVM: arm64: Support stolen time reporting via shared
    structure (bsc#1172197 jsc#SLE-13593).

  - KVM: arm64: Use the correct timer structure to access
    the physical counter (bsc#1133021).

  - KVM: arm/arm64: Correct AArch32 SPSR on exception entry
    (bsc#1133021).

  - KVM: arm/arm64: Correct CPSR on exception entry
    (bsc#1133021).

  - KVM: arm/arm64: Factor out hypercall handling from PSCI
    code (bsc#1172197 jsc#SLE-13593).

  - KVM: arm/arm64: Factor out hypercall handling from PSCI
    code (bsc#1172197 jsc#SLE-13593).

  - KVM: arm: vgic: Fix limit condition when writing to
    GICD_IACTIVER (bsc#1133021).

  - KVM: Implement kvm_put_guest() (bsc#1172197
    jsc#SLE-13593).

  - KVM: nVMX: always update CR3 in VMCS (git-fixes).

  - KVM: Play nice with read-only memslots when querying
    host page size (bsc#1133021).

  - KVM: s390: Remove false WARN_ON_ONCE for the PQAP
    instruction (bsc#1133021).

  - l2tp: add sk_family checks to l2tp_validate_socket
    (networking-stable-20_06_07).

  - l2tp: do not use inet_hash()/inet_unhash()
    (networking-stable-20_06_07).

  - leds: 88pm860x: fix use-after-free on unbind
    (git-fixes).

  - leds: core: Flush scheduled work for system suspend
    (git-fixes).

  - leds: da903x: fix use-after-free on unbind (git-fixes).

  - leds: gpio: Fix semantic error (git-fixes).

  - leds: lm3533: fix use-after-free on unbind (git-fixes).

  - leds: lm355x: avoid enum conversion warning (git-fixes).

  - leds: lm36274: fix use-after-free on unbind (git-fixes).

  - leds: wm831x-status: fix use-after-free on unbind
    (git-fixes).

  - libbpf: Wrap source argument of BPF_CORE_READ macro in
    parentheses (bsc#1155518).

  - lib: Reduce user_access_begin() boundaries in
    strncpy_from_user() and strnlen_user() (bsc#1174331).

  - liquidio: Fix wrong return value in cn23xx_get_pf_num()
    (git-fixes).

  - locktorture: Print ratio of acquisitions, not failures
    (bsc#1149032).

  - mac80211: allow rx of mesh eapol frames with default rx
    key (git-fixes).

  - mac80211: fix misplaced while instead of if (git-fixes).

  - mac80211: mesh: Free ie data when leaving mesh
    (git-fixes).

  - mac80211: mesh: Free pending skb when destroying a mpath
    (git-fixes).

  - media: cec: silence shift wrapping warning in
    __cec_s_log_addrs() (git-fixes).

  - media: cxusb-analog: fix V4L2 dependency (git-fixes).

  - media: exynos4-is: Add missed check for
    pinctrl_lookup_state() (git-fixes).

  - media: firewire: Using uninitialized values in
    node_probe() (git-fixes).

  - media: marvell-ccic: Add missed
    v4l2_async_notifier_cleanup() (git-fixes).

  - media: media-request: Fix crash if memory allocation
    fails (git-fixes).

  - media: nuvoton-cir: remove setting tx carrier functions
    (git-fixes).

  - media: omap3isp: Add missed v4l2_ctrl_handler_free() for
    preview_init_entities() (git-fixes).

  - media: sur40: Remove uninitialized_var() usage
    (git-fixes).

  - media: vsp1: dl: Fix NULL pointer dereference on unbind
    (git-fixes).

  - mei: bus: do not clean driver pointer (git-fixes).

  - mfd: arizona: Ensure 32k clock is put on driver unbind
    and error (git-fixes).

  - mfd: dln2: Run event handler loop under spinlock
    (git-fixes).

  - mfd: intel-lpss: Add Intel Jasper Lake PCI IDs
    (jsc#SLE-12602).

  - mlxsw: core: Fix wrong SFP EEPROM reading for upper
    pages 1-3 (bsc#1154488).

  - mlxsw: core: Use different get_trend() callbacks for
    different thermal zones (networking-stable-20_06_10).

  - mmc: meson-gx: limit segments to 1 when
    dram-access-quirk is needed (git-fixes).

  - mmc: sdhci: do not enable card detect interrupt for gpio
    cd type (git-fixes).

  - mm: Fix protection usage propagation (bsc#1174002).

  - mm/mmap.c: close race between munmap() and
    expand_upwards()/downwards() (bsc#1174527).

  - mtd: properly check all write ioctls for permissions
    (git-fixes).

  - mtd: rawnand: fsl_upm: Remove unused mtd var
    (git-fixes).

  - mtd: rawnand: qcom: avoid write to unavailable register
    (git-fixes).

  - mwifiex: Fix firmware filename for sd8977 chipset
    (git-fixes).

  - mwifiex: Fix firmware filename for sd8997 chipset
    (git-fixes).

  - mwifiex: Prevent memory corruption handling keys
    (git-fixes).

  - nbd: Fix memory leak in nbd_add_socket (git-fixes).

  - ndctl/papr_scm,uapi: Add support for PAPR nvdimm
    specific methods (bsc#1175052 jsc#SLE-13823 bsc#1174969
    jsc#SLE-12769).

  - net: be more gentle about silly gso requests coming from
    user (networking-stable-20_06_07).

  - net/bpfilter: Initialize pos in
    __bpfilter_process_sockopt (bsc#1155518).

  - net/bpfilter: split __bpfilter_process_sockopt
    (bsc#1155518).

  - net: check untrusted gso_size at kernel entry
    (networking-stable-20_06_07).

  - netdevsim: fix unbalaced locking in nsim_create()
    (git-fixes).

  - net: dsa: bcm_sf2: Fix node reference count (git-fixes).

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

  - net: ena: avoid memory access violation by validating
    req_id properly (bsc#1174852).

  - net: ena: avoid unnecessary admin command when RSS
    function set fails (bsc#1174852).

  - net: ena: avoid unnecessary rearming of interrupt vector
    when busy-polling (bsc#1174852).

  - net: ena: change default RSS hash function to Toeplitz
    (bsc#1174852).

  - net: ena: changes to RSS hash key allocation
    (bsc#1174852).

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

  - net: ena: ethtool: clean up minor indentation issue
    (bsc#1174852).

  - net: ena: ethtool: remove redundant non-zero check on rc
    (bsc#1174852).

  - net/ena: Fix build warning in ena_xdp_set()
    (bsc#1174852).

  - net: ena: fix continuous keep-alive resets
    (bsc#1174852).

  - net: ena: fix ena_com_comp_status_to_errno() return
    value (bsc#1174852).

  - net: ena: fix error returning in
    ena_com_get_hash_function() (bsc#1174852).

  - net: ena: fix request of incorrect number of IRQ vectors
    (bsc#1174852).

  - net: ena: Fix using plain integer as NULL pointer in
    ena_init_napi_in_range (bsc#1174852).

  - net: ena: Make some functions static (bsc#1174852).

  - net: ena: move llq configuration from ena_probe to
    ena_device_init() (bsc#1174852).

  - net: ena: reduce driver load time (bsc#1174852).

  - net: ena: remove code that does nothing (bsc#1174852).

  - net: ena: remove set but not used variable 'hash_key'
    (bsc#1174852).

  - net: ena: rename ena_com_free_desc to make API more
    uniform (bsc#1174852).

  - net: ena: simplify
    ena_com_update_intr_delay_resolution() (bsc#1174852).

  - net: ena: support new LLQ acceleration mode
    (bsc#1174852).

  - net: ena: use explicit variable size for clarity
    (bsc#1174852).

  - net: ena: use SHUTDOWN as reset reason when closing
    interface (bsc#1174852).

  - net_failover: fixed rollback in net_failover_open()
    (networking-stable-20_06_10).

  - netfilter: ip6tables: Add a .pre_exit hook in all
    ip6table_foo.c (bsc#1171857).

  - netfilter: ip6tables: Split ip6t_unregister_table() into
    pre_exit and exit helpers (bsc#1171857).

  - netfilter: iptables: Add a .pre_exit hook in all
    iptable_foo.c (bsc#1171857).

  - netfilter: iptables: Split ipt_unregister_table() into
    pre_exit and exit helpers (bsc#1171857).

  - net: Fix a documentation bug wrt.
    ip_unprivileged_port_start (git-fixes). (SLES tuning
    guide refers to ip-sysctl.txt.)

  - net: fsl/fman: treat all RGMII modes in
    memac_adjust_link() (bsc#1174398).

  - net: hns3: check reset pending after FLR prepare
    (bsc#1154353).

  - net: hns3: fix error handling for desc filling
    (git-fixes).

  - net: hns3: fix for not calculating TX BD send size
    correctly (git-fixes).

  - net: hns3: fix return value error when query MAC link
    status fail (git-fixes).

  - net: ipv4: Fix wrong type conversion from hint to rt in
    ip_route_use_hint() (bsc#1154353).

  - net: lan78xx: add missing endpoint sanity check
    (git-fixes).

  - net: lan78xx: fix transfer-buffer memory leak
    (git-fixes).

  - net: lan78xx: replace bogus endpoint lookup (git-fixes).

  - net: macb: call pm_runtime_put_sync on failure path
    (git-fixes).

  - net/mlx5: drain health workqueue in case of driver load
    error (networking-stable-20_06_16).

  - net/mlx5e: Fix CPU mapping after function reload to
    avoid aRFS RX crash (jsc#SLE-8464).

  - net/mlx5e: Fix CPU mapping after function reload to
    avoid aRFS RX crash (jsc#SLE-8464).

  - net/mlx5e: Fix kernel crash when setting vf VLANID on a
    VF dev (jsc#SLE-8464).

  - net/mlx5e: Fix kernel crash when setting vf VLANID on a
    VF dev (jsc#SLE-8464).

  - net/mlx5e: Fix repeated XSK usage on one channel
    (networking-stable-20_06_16).

  - net/mlx5e: Fix VXLAN configuration restore after
    function reload (jsc#SLE-8464).

  - net/mlx5e: Fix VXLAN configuration restore after
    function reload (jsc#SLE-8464).

  - net/mlx5: E-switch, Destroy TSAR when fail to enable the
    mode (jsc#SLE-8464).

  - net/mlx5: E-switch, Destroy TSAR when fail to enable the
    mode (jsc#SLE-8464).

  - net/mlx5: Fix fatal error handling during device load
    (networking-stable-20_06_16).

  - net: phy: Check harder for errors in get_phy_id()
    (git-fixes).

  - net: phy: fix memory leak in device-create error path
    (git-fixes).

  - net: phy: realtek: add support for configuring the RX
    delay on RTL8211F (bsc#1174398).

  - net, sk_msg: Clear sk_user_data pointer on clone if
    tagged (bsc#1155518).

  - net, sk_msg: Do not use RCU_INIT_POINTER on sk_user_data
    (bsc#1155518).

  - net/smc: fix restoring of fallback changes (git-fixes).

  - net: stmmac: do not attach interface until resume
    finishes (bsc#1174072).

  - net: stmmac: dwc-qos: avoid clk and reset for acpi
    device (bsc#1174072).

  - net: stmmac: dwc-qos: use generic device api
    (bsc#1174072).

  - net: stmmac: enable timestamp snapshot for required PTP
    packets in dwmac v5.10a (networking-stable-20_06_07).

  - net: stmmac: platform: fix probe for ACPI devices
    (bsc#1174072).

  - net/tls: fix encryption error checking (git-fixes).

  - net/tls: free record only on encryption error
    (git-fixes).

  - net: usb: qmi_wwan: add Telit LE910C1-EUX composition
    (networking-stable-20_06_07).

  - nfc: nci: add missed destroy_workqueue in
    nci_register_device (git-fixes).

  - nfc: s3fwrn5: add missing release on skb in
    s3fwrn5_recv_frame (git-fixes).

  - nfp: flower: fix used time of merge flow statistics
    (networking-stable-20_06_07).

  - NFS: Fix interrupted slots by sending a solo SEQUENCE
    operation (bsc#1174264).

  - NTB: Fix static check warning in perf_clear_test
    (git-fixes).

  - NTB: Fix the default port and peer numbers for legacy
    drivers (git-fixes).

  - ntb: hw: remove the code that sets the DMA mask
    (git-fixes).

  - NTB: ntb_pingpong: Choose doorbells based on port number
    (git-fixes).

  - NTB: ntb_test: Fix bug when counting remote files
    (git-fixes).

  - NTB: ntb_tool: reading the link file should not end in a
    NULL byte (git-fixes).

  - NTB: perf: Do not require one more memory window than
    number of peers (git-fixes).

  - NTB: perf: Fix race condition when run with ntb_test
    (git-fixes).

  - NTB: perf: Fix support for hardware that does not have
    port numbers (git-fixes).

  - ntb_perf: pass correct struct device to
    dma_alloc_coherent (git-fixes).

  - NTB: Revert the change to use the NTB device dev for DMA
    allocations (git-fixes).

  - ntb_tool: pass correct struct device to
    dma_alloc_coherent (git-fixes).

  - ocfs2: avoid inode removal while nfsd is accessing it
    (bsc#1172963).

  - ocfs2: fix panic on nfs server over ocfs2 (bsc#1172963).

  - ocfs2: fix remounting needed after setfacl command
    (bsc#1173954).

  - ocfs2: load global_inode_alloc (bsc#1172963).

  - omapfb: dss: Fix max fclk divider for omap36xx
    (git-fixes).

  - ovl: inode reference leak in ovl_is_inuse true case
    (git-fixes).

  - padata: add separate cpuhp node for CPUHP_PADATA_DEAD
    (git-fixes).

  - padata: kABI fixup for struct padata_instance splitting
    nodes (git-fixes).

  - PCI/AER: Remove HEST/FIRMWARE_FIRST parsing for AER
    ownership (bsc#1174356).

  - PCI/AER: Use only _OSC to determine AER ownership
    (bsc#1174356).

  - PCI/ASPM: Add missing newline in sysfs 'policy'
    (git-fixes).

  - PCI/ASPM: Disable ASPM on ASMedia ASM1083/1085
    PCIe-to-PCI bridge (git-fixes).

  - PCI: cadence: Fix updating Vendor ID and Subsystem
    Vendor ID register (git-fixes).

  - PCI/EDR: Log only ACPI_NOTIFY_DISCONNECT_RECOVER events
    (bsc#1174513).

  - PCI: Fix pci_cfg_wait queue locking problem (git-fixes).

  - PCI: hotplug: ACPI: Fix context refcounting in
    acpiphp_grab_context() (git-fixes).

  - PCI: hv: Add support for protocol 1.3 and support
    PCI_BUS_RELATIONS2 (bsc#1172201).

  - PCI: qcom: Add missing ipq806x clocks in PCIe driver
    (git-fixes).

  - PCI: qcom: Add missing reset for ipq806x (git-fixes).

  - PCI: qcom: Add support for tx term offset for rev 2.1.0
    (git-fixes).

  - PCI: qcom: Define some PARF params needed for ipq8064
    SoC (git-fixes).

  - PCI: rcar: Fix runtime PM imbalance on error
    (git-fixes).

  - PCI: Release IVRS table in AMD ACS quirk (git-fixes).

  - pci: Revive pci_dev __aer_firmware_first* fields for
    kABI (bsc#1174356).

  - PCI: switchtec: Add missing __iomem and __user tags to
    fix sparse warnings (git-fixes).

  - PCI: switchtec: Add missing __iomem tag to fix sparse
    warnings (git-fixes).

  - PCI: tegra: Revert tegra124 raw_violation_fixup
    (git-fixes).

  - percpu: Separate decrypted varaibles anytime encryption
    can be enabled (bsc#1174332).

  - phy: armada-38x: fix NETA lockup when repeatedly
    switching speeds (git-fixes).

  - phy: exynos5-usbdrd: Calibrating makes sense only for
    USB2.0 PHY (git-fixes).

  - phy: renesas: rcar-gen3-usb2: move irq registration to
    init (git-fixes).

  - phy: sun4i-usb: fix dereference of pointer phy0 before
    it is null checked (git-fixes).

  - pinctrl: amd: fix npins for uart0 in kerncz_groups
    (git-fixes).

  - pinctrl: ingenic: Enhance support for IRQ_TYPE_EDGE_BOTH
    (git-fixes).

  - pinctrl: single: fix function name in documentation
    (git-fixes).

  - pinctrl-single: fix pcs_parse_pinconf() return value
    (git-fixes).

  - platform/chrome: cros_ec_ishtp: Fix a double-unlock
    issue (git-fixes).

  - platform/x86: intel-hid: Fix return value check in
    check_acpi_dev() (git-fixes).

  - platform/x86: intel-vbtn: Fix return value check in
    check_acpi_dev() (git-fixes).

  - platform/x86: ISST: Increase timeout (bsc#1174185).

  - PM: wakeup: Show statistics for deleted wakeup sources
    again (git-fixes).

  - powerpc/64s: Fix early_init_mmu section mismatch
    (bsc#1065729).

  - powerpc: Allow 4224 bytes of stack expansion for the
    signal frame (bsc#1065729).

  - powerpc/book3s64/pkeys: Fix pkey_access_permitted() for
    execute disable pkey (bsc#1065729).

  - powerpc/book3s64/pkeys: Use PVR check instead of cpu
    feature (bsc#1065729).

  - powerpc/boot: Fix CONFIG_PPC_MPC52XX references
    (bsc#1065729).

  - powerpc: Document details on H_SCM_HEALTH hcall
    (bsc#1175052 jsc#SLE-13823 bsc#1174969 jsc#SLE-12769).

  - powerpc/eeh: Fix pseries_eeh_configure_bridge()
    (bsc#1174689).

  - powerpc/fadump: fix race between pstore write and fadump
    crash trigger (bsc#1168959 ltc#185010).

  - powerpc/kasan: Fix issues by lowering KASAN_SHADOW_END
    (git-fixes).

  - powerpc/nvdimm: Use HCALL error as the return value
    (bsc#1175284).

  - powerpc/nvdimm: use H_SCM_QUERY hcall on H_OVERLAP error
    (bsc#1175284).

  - powerpc/papr_scm: Add support for fetching nvdimm
    'fuel-gauge' metric (bsc#1175052 jsc#SLE-13823
    bsc#1174969 jsc#SLE-12769).

  - powerpc/papr_scm: Fetch nvdimm health information from
    PHYP (bsc#1175052 jsc#SLE-13823 bsc#1174969
    jsc#SLE-12769).

  - powerpc/papr_scm: Fetch nvdimm performance stats from
    PHYP (bsc#1175052 jsc#SLE-13823 bsc#1174969
    jsc#SLE-12769).

  - powerpc/papr_scm: Implement support for PAPR_PDSM_HEALTH
    (bsc#1175052 jsc#SLE-13823 bsc#1174969 jsc#SLE-12769).

  - powerpc/papr_scm: Improve error logging and handling
    papr_scm_ndctl() (bsc#1175052 jsc#SLE-13823 bsc#1174969
    jsc#SLE-12769).

  - powerpc/papr_scm: Mark papr_scm_ndctl() as static
    (bsc#1175052 jsc#SLE-13823 bsc#1174969 jsc#SLE-12769).

  - powerpc/pseries/hotplug-cpu: Remove double free in error
    path (bsc#1065729).

  - powerpc/pseries: PCIE PHB reset (bsc#1174689).

  - powerpc/pseries: remove cede offline state for CPUs
    (bsc#1065729).

  - powerpc/rtas: do not online CPUs for partition suspend
    (bsc#1065729).

  - powerpc/vdso: Fix vdso cpu truncation (bsc#1065729).

  - powerpc/xmon: Reset RCU and soft lockup watchdogs
    (bsc#1065729).

  - power: supply: check if calc_soc succeeded in
    pm860x_init_battery (git-fixes).

  - pwm: bcm-iproc: handle clk_get_rate() return
    (git-fixes).

  - qed: suppress 'do not support RoCE & iWARP' flooding on
    HW init (git-fixes).

  - qed: suppress false-positives interrupt error messages
    on HW init (git-fixes).

  - r8169: fix jumbo configuration for RTL8168evl
    (bsc#1175296).

  - r8169: fix jumbo packet handling on resume from suspend
    (bsc#1175296).

  - r8169: fix resume on cable plug-in (bsc#1175296).

  - r8169: fix rtl_hw_jumbo_disable for RTL8168evl
    (bsc#1175296).

  - r8169: move disabling interrupt coalescing to
    RTL8169/RTL8168 init (bsc#1175296).

  - r8169: read common register for PCI commit
    (bsc#1175296).

  - random32: move the pseudo-random 32-bit definitions to
    prandom.h (git-fixes).

  - random32: remove net_rand_state from the latent entropy
    gcc plugin (git-fixes).

  - random: fix circular include dependency on arm64 after
    addition of percpu.h (git-fixes).

  - RDMA/cm: Add missing locking around id.state in
    cm_dup_req_handler (git-fixes).

  - RDMA/cma: Protect bind_list and listen_list while
    finding matching cm id (git-fixes).

  - RDMA/cm: Fix an error check in cm_alloc_id_priv()
    (git-fixes).

  - RDMA/cm: Fix checking for allowed duplicate listens
    (git-fixes).

  - RDMA/cm: Fix ordering of xa_alloc_cyclic() in
    ib_create_cm_id() (git-fixes).

  - RDMA/cm: Read id.state under lock when doing pr_debug()
    (git-fixes).

  - RDMA/cm: Remove a race freeing timewait_info
    (git-fixes).

  - RDMA/cm: Update num_paths in cma_resolve_iboe_route
    error flow (git-fixes).

  - RDMA/core: Fix double destruction of uobject
    (git-fixes).

  - RDMA/core: Fix double put of resource (git-fixes).

  - RDMA/core: Fix missing error check on dev_set_name()
    (git-fixes).

  - RDMA/core: Fix protection fault in ib_mr_pool_destroy
    (git-fixes).

  - RDMA/core: Fix race between destroy and release FD
    object (git-fixes).

  - RDMA/core: Fix race in rdma_alloc_commit_uobject()
    (git-fixes).

  - RDMA/core: Prevent mixed use of FDs between shared
    ufiles (git-fixes).

  - RDMA/counter: Query a counter before release
    (git-fixes).

  - RDMA/efa: Set maximum pkeys device attribute
    (git-fixes).

  - RDMA/hns: Bugfix for querying qkey (git-fixes).

  - RDMA/hns: Fix cmdq parameter of querying pf timer
    resource (git-fixes).

  - RDMA/iwcm: Fix iwcm work deallocation (git-fixes).

  - RDMA/iw_cxgb4: Fix incorrect function parameters
    (git-fixes).

  - RDMA/mad: Do not crash if the rdma device does not have
    a umad interface (git-fixes).

  - RDMA/mad: Fix possible memory leak in
    ib_mad_post_receive_mads() (git-fixes).

  - RDMA/mlx4: Initialize ib_spec on the stack (git-fixes).

  - RDMA/mlx5: Add init2init as a modify command
    (git-fixes).

  - RDMA/mlx5: Fix access to wrong pointer while performing
    flush due to error (git-fixes).

  - RDMA/mlx5: Fix prefetch memory leak if
    get_prefetchable_mr fails (jsc#SLE-8446).

  - RDMA/mlx5: Fix prefetch memory leak if
    get_prefetchable_mr fails (jsc#SLE-8446).

  - RDMA/mlx5: Fix the number of hwcounters of a dynamic
    counter (git-fixes).

  - RDMA/mlx5: Fix udata response upon SRQ creation
    (git-fixes).

  - RDMA/mlx5: Prevent prefetch from racing with implicit
    destruction (jsc#SLE-8446).

  - RDMA/mlx5: Prevent prefetch from racing with implicit
    destruction (jsc#SLE-8446).

  - RDMA/mlx5: Set GRH fields in query QP on RoCE
    (git-fixes).

  - RDMA/mlx5: Use xa_lock_irq when access to SRQ table
    (git-fixes).

  - RDMA/mlx5: Verify that QP is created with RQ or SQ
    (git-fixes).

  - RDMA/nldev: Fix crash when set a QP to a new counter but
    QPN is missing (git-fixes).

  - RDMA/pvrdma: Fix missing pci disable in
    pvrdma_pci_probe() (git-fixes).

  - RDMA/qedr: Fix KASAN: use-after-free in
    ucma_event_handler+0x532 (git-fixes).

  - RDMA/rvt: Fix potential memory leak caused by
    rvt_alloc_rq (git-fixes).

  - RDMA/rxe: Always return ERR_PTR from
    rxe_create_mmap_info() (git-fixes).

  - RDMA/rxe: Fix configuration of atomic queue pair
    attributes (git-fixes).

  - RDMA/rxe: Set default vendor ID (git-fixes).

  - RDMA/rxe: Set sys_image_guid to be aligned with HW IB
    devices (git-fixes).

  - RDMA/siw: Fix failure handling during device creation
    (git-fixes).

  - RDMA/siw: Fix passive connection establishment
    (git-fixes).

  - RDMA/siw: Fix pointer-to-int-cast warning in
    siw_rx_pbl() (git-fixes).

  - RDMA/siw: Fix potential siw_mem refcnt leak in
    siw_fastreg_mr() (git-fixes).

  - RDMA/siw: Fix reporting vendor_part_id (git-fixes).

  - RDMA/siw: Fix setting active_mtu attribute (git-fixes).

  - RDMA/siw: Fix setting active_(speed, width) attributes
    (git-fixes).

  - RDMA/ucma: Put a lock around every call to the rdma_cm
    layer (git-fixes).

  - RDMA/uverbs: Fix create WQ to use the given user handle
    (git-fixes).

  - regmap: debugfs: check count when read regmap file
    (git-fixes).

  - regmap: debugfs: Do not sleep while atomic for fast_io
    regmaps (git-fixes).

  - regmap: dev_get_regmap_match(): fix string comparison
    (git-fixes).

  - regmap: fix alignment issue (git-fixes).

  - regmap: Fix memory leak from regmap_register_patch
    (git-fixes).

  - regulator: gpio: Honor regulator-boot-on property
    (git-fixes).

  - remoteproc: qcom_q6v5_mss: Validate MBA firmware size
    before load (git-fixes).

  - remoteproc: qcom_q6v5_mss: Validate modem blob firmware
    size before load (git-fixes).

  - remoteproc: qcom: q6v5: Update running state before
    requesting stop (git-fixes).

  - Revert 'ALSA: hda: call runtime_allow() for all hda
    controllers' (git-fixes).

  - Revert 'drm/amd/display: Expose connector VRR range via
    debugfs' (bsc#1152489) &#9;* refreshed for context
    changes

  - Revert 'drm/amdgpu: Fix NULL dereference in dpm sysfs
    handlers' (git-fixes).

  - Revert 'i2c: cadence: Fix the hold bit setting'
    (git-fixes).

  - Revert 'RDMA/cma: Simplify rdma_resolve_addr() error
    flow' (git-fixes).

  - Revert 'thermal: mediatek: fix register index error'
    (git-fixes).

  - rhashtable: Document the right function parameters
    (bsc#1174880).

  - rhashtable: drop duplicated word in <linux/rhashtable.h>
    (bsc#1174880).

  - rhashtable: Drop raw RCU deref in nested_table_free
    (bsc#1174880).

  - rhashtable: Fix unprotected RCU dereference in __rht_ptr
    (bsc#1174880).

  - rhashtable: Restore RCU marking on rhash_lock_head
    (bsc#1174880).

  - RMDA/cm: Fix missing ib_cm_destroy_id() in
    ib_cm_insert_listen() (git-fixes).

  - rpm/kernel-obs-build.spec.in: Enable overlayfs Overlayfs
    is needed for podman or docker builds when no more
    specific driver can be used (like lvm or btrfs). As the
    default build fs is ext4 currently, we need overlayfs
    kernel modules to be available.

  - rpm/modules.fips: add ecdh_generic (boo#1173813)

  - rtlwifi: rtl8192cu: Remove uninitialized_var() usage
    (git-fixes).

  - rtnetlink: Fix memory(net_device) leak when ->newlink
    fails (bsc#1154353).

  - rtnetlink: Fix memory(net_device) leak when ->newlink
    fails (git-fixes).

  - rtw88: fix LDPC field for RA info (git-fixes).

  - rtw88: fix short GI capability based on current
    bandwidth (git-fixes).

  - s390: fix syscall_get_error for compat processes
    (git-fixes).

  - s390/ism: fix error return code in ism_probe()
    (git-fixes).

  - s390/kaslr: add support for R_390_JMP_SLOT relocation
    type (git-fixes).

  - s390/pci: Fix s390_mmio_read/write with MIO (git-fixes).

  - s390/qdio: consistently restore the IRQ handler
    (git-fixes).

  - s390/qdio: put thinint indicator after early error
    (git-fixes).

  - s390/qdio: tear down thinint indicator after early error
    (git-fixes).

  - s390/qeth: fix error handling for isolation mode cmds
    (git-fixes).

  - sched/fair: handle case of task_h_load() returning 0
    (bnc#1155798 (CPU scheduler functional and performance
    backports)).

  - scsi: ipr: Fix softlockup when rescanning devices in
    petitboot (jsc#SLE-13654).

  - scsi: ipr: Fix softlockup when rescanning devices in
    petitboot (jsc#SLE-13654).

  - scsi: ipr: remove unneeded semicolon (jsc#SLE-13654).

  - scsi: ipr: Use scnprintf() for avoiding potential buffer
    overflow (jsc#SLE-13654).

  - scsi: ipr: Use scnprintf() for avoiding potential buffer
    overflow (jsc#SLE-13654).

  - scsi: libfc: free response frame from GPN_ID
    (bsc#1173849).

  - scsi: libfc: Handling of extra kref (bsc#1173849).

  - scsi: libfc: If PRLI rejected, move rport to PLOGI state
    (bsc#1173849).

  - scsi: libfc: rport state move to PLOGI if all PRLI retry
    exhausted (bsc#1173849).

  - scsi: libfc: Skip additional kref updating work event
    (bsc#1173849).

  - scsi: ufs-bsg: Fix runtime PM imbalance on error
    (git-fixes).

  - scsi: zfcp: Fix panic on ERP timeout for previously
    dismissed ERP action (git-fixes).

  - selftests/net: in rxtimestamp getopt_long needs
    terminating null entry (networking-stable-20_06_16).

  - selinux: fall back to ref-walk if audit is required
    (bsc#1174333).

  - selinux: revert 'stop passing MAY_NOT_BLOCK to the AVC
    upon follow_link' (bsc#1174333).

  - seq_buf: Export seq_buf_printf (bsc#1175052
    jsc#SLE-13823 bsc#1174969 jsc#SLE-12769).

  - seq_buf: Export seq_buf_printf (bsc#1175052
    jsc#SLE-13823 bsc#1174969 jsc#SLE-12769).

  - serial: 8250: fix null-ptr-deref in
    serial8250_start_tx() (git-fixes).

  - serial: 8250_mtk: Fix high-speed baud rates clamping
    (git-fixes).

  - serial: 8250_pci: Move Pericom IDs to pci_ids.h
    (git-fixes).

  - serial: 8250_tegra: Create Tegra specific 8250 driver
    (bsc#1173941).

  - serial: amba-pl011: Make sure we initialize the
    port.lock spinlock (git-fixes).

  - serial: exar: Fix GPIO configuration for Sealevel cards
    based on XR17V35X (git-fixes).

  - serial: mxs-auart: add missed iounmap() in probe failure
    and remove (git-fixes).

  - serial: tegra: fix CREAD handling for PIO (git-fixes).

  - SMB3: Honor lease disabling for multiuser mounts
    (git-fixes).

  - soc/tegra: pmc: Enable PMIC wake event on Tegra210
    (bsc#1175116).

  - soundwire: intel: fix memory leak with devm_kasprintf
    (git-fixes).

  - spi: davinci: Remove uninitialized_var() usage
    (git-fixes).

  - spi: lantiq: fix: Rx overflow error in full duplex mode
    (git-fixes).

  - spi: lantiq-ssc: Fix warning by using WQ_MEM_RECLAIM
    (git-fixes).

  - spi: mediatek: use correct SPI_CFG2_REG MACRO
    (git-fixes).

  - spi: rockchip: Fix error in SPI slave pio read
    (git-fixes).

  - spi: spidev: fix a potential use-after-free in
    spidev_release() (git-fixes).

  - spi: spidev: fix a race between spidev_release and
    spidev_remove (git-fixes).

  - spi: spi-geni-qcom: Actually use our FIFO (git-fixes).

  - spi: spi-sun6i: sun6i_spi_transfer_one(): fix setting of
    clock rate (git-fixes).

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

  - staging: comedi: verify array index is correct before
    using it (git-fixes).

  - Staging: rtl8188eu: rtw_mlme: Fix uninitialized variable
    authmode (git-fixes).

  - staging: rtl8192u: fix a dubious looking mask before a
    shift (git-fixes).

  - staging: rtl8712: handle firmware load failure
    (git-fixes).

  - staging: vchiq_arm: Add a matching unregister call
    (git-fixes).

  - staging: wlan-ng: properly check endpoint types
    (git-fixes).

  - SUNRPC dont update timeout value on connection reset
    (bsc#1174263).

  - sunrpc: Fix gss_unwrap_resp_integ() again (bsc#1174116).

  - tcp: md5: allow changing MD5 keys in all socket states
    (git-fixes).

  - thermal/drivers: imx: Fix missing of_node_put() at probe
    time (git-fixes).

  - thermal: int3403_thermal: Downgrade error message
    (git-fixes).

  - thermal: ti-soc-thermal: Fix reversed condition in
    ti_thermal_expose_sensor() (git-fixes).

  - tpm_crb: fix fTPM on AMD Zen+ CPUs (bsc#1174362).

  - tpm: Require that all digests are present in
    TCG_PCR_EVENT2 structures (git-fixes).

  - tpm_tis: extra chip->ops check on error path in
    tpm_tis_core_init (git-fixes).

  - tty: hvc_console, fix crashes on parallel open/close
    (git-fixes).

  - ubsan: check panic_on_warn (bsc#1174805).

  - udp: Copy has_conns in reuseport_grow() (git-fixes).

  - udp: Improve load balancing for SO_REUSEPORT
    (git-fixes).

  - uio_pdrv_genirq: Remove warning when irq is not
    specified (bsc#1174762).

  - USB: c67x00: fix use after free in c67x00_giveback_urb
    (git-fixes).

  - usb: chipidea: core: add wakeup support for extcon
    (git-fixes).

  - usb: core: fix quirks_param_set() writing to a const
    pointer (git-fixes).

  - usb: dwc2: Fix shutdown callback in platform
    (git-fixes).

  - usb: dwc2: gadget: Make use of GINTMSK2 (git-fixes).

  - usb: dwc3: pci: add support for the Intel Jasper Lake
    (git-fixes).

  - usb: dwc3: pci: add support for the Intel Tiger Lake PCH
    -H variant (git-fixes).

  - usb: dwc3: pci: Fix reference count leak in
    dwc3_pci_resume_work (git-fixes).

  - usb: gadget: Fix issue with config_ep_by_speed function
    (git-fixes).

  - usb: gadget: f_uac2: fix AC Interface Header Descriptor
    wTotalLength (git-fixes).

  - usb: gadget: function: fix missing spinlock in
    f_uac1_legacy (git-fixes).

  - usb: gadget: udc: atmel: fix uninitialized read in debug
    printk (git-fixes).

  - usb: gadget: udc: atmel: remove outdated comment in
    usba_ep_disable() (git-fixes).

  - usb: gadget: udc: gr_udc: fix memleak on error handling
    path in gr_ep_init() (git-fixes).

  - usb: hso: check for return value in
    hso_serial_common_create() (git-fixes).

  - usb: hso: Fix debug compile warning on sparc32
    (git-fixes).

  - USB: iowarrior: fix up report size handling for some
    devices (git-fixes).

  - usbip: tools: fix module name in man page (git-fixes).

  - usbnet: smsc95xx: Fix use-after-free after removal
    (git-fixes).

  - USB: serial: ch341: add new Product ID for CH340
    (git-fixes).

  - USB: serial: cp210x: enable usb generic
    throttle/unthrottle (git-fixes).

  - USB: serial: cp210x: re-enable auto-RTS on open
    (git-fixes).

  - USB: serial: cypress_m8: enable Simply Automated UPB PIM
    (git-fixes).

  - USB: serial: iuu_phoenix: fix led-activity helpers
    (git-fixes).

  - USB: serial: iuu_phoenix: fix memory corruption
    (git-fixes).

  - USB: serial: option: add GosunCn GM500 series
    (git-fixes).

  - USB: serial: option: add Quectel EG95 LTE modem
    (git-fixes).

  - USB: serial: qcserial: add EM7305 QDL product ID
    (git-fixes).

  - usb: tegra: Fix allocation for the FPCI context
    (git-fixes).

  - usb: xhci: define IDs for various ASMedia host
    controllers (git-fixes).

  - usb: xhci: Fix ASM2142/ASM3142 DMA addressing
    (git-fixes).

  - usb: xhci: Fix ASMedia ASM1142 DMA addressing
    (git-fixes).

  - usb: xhci-mtk: fix the failure of bandwidth allocation
    (git-fixes).

  - vfio/pci: Fix SR-IOV VF handling with MMIO blocking
    (bsc#1174129).

  - video: fbdev: sm712fb: fix an issue about iounmap for a
    wrong address (git-fixes).

  - video: pxafb: Fix the function used to balance a
    'dma_alloc_coherent()' call (git-fixes).

  - virtio: virtio_console: add missing
    MODULE_DEVICE_TABLE() for rproc serial (git-fixes).

  - virt: vbox: Fix guest capabilities mask check
    (git-fixes).

  - virt: vbox: Fix VBGL_IOCTL_VMMDEV_REQUEST_BIG and _LOG
    req numbers to match upstream (git-fixes).

  - vsock: fix timeout in vsock_accept()
    (networking-stable-20_06_07).

  - vt: Reject zero-sized screen buffer size (git-fixes).

  - vxlan: Avoid infinite loop when suppressing NS messages
    with invalid options (networking-stable-20_06_10).

  - watchdog: f71808e_wdt: clear watchdog timeout occurred
    flag (git-fixes).

  - watchdog: f71808e_wdt: indicate WDIOF_CARDRESET support
    in watchdog_info.options (git-fixes).

  - watchdog: f71808e_wdt: remove use of wrong watchdog_info
    option (git-fixes).

  - watchdog: initialize device before misc_register
    (git-fixes).

  - watchdog: iTCO: Add support for Cannon Lake PCH iTCO
    (jsc#SLE-13202).

  - watchdog: iTCO: Add support for Cannon Lake PCH iTCO
    (jsc#SLE-13202).

  - wireless: Use linux/stddef.h instead of stddef.h
    (git-fixes).

  - wireless: Use offsetof instead of custom macro
    (git-fixes).

  - wl1251: fix always return 0 error (git-fixes).

  - workqueue: Remove unnecessary kfree() call in
    rcu_free_wq() (git-fixes).

  - xen/pvcalls-back: test for errors when calling
    backend_connect() (bsc#1065600).

  - xfrm: fix a warning in xfrm_policy_insert_list
    (bsc#1174645).

  - xfrm: policy: match with both mark and mask on user
    interfaces (bsc#1174645).

  - xfs: do not eat an EIO/ENOSPC writeback error when
    scrubbing data fork (git-fixes).

  - xfs: fix inode allocation block res calculation
    precedence (git-fixes).

  - xfs: fix reflink quota reservation accounting error
    (git-fixes).

  - xfs: preserve rmapbt swapext block reservation from
    freed blocks (git-fixes)."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149032"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154488"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175377"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15780");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpdk-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-preempt-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdpdk-20_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdpdk-20_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mhvtl-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-fuse_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-fuse_client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openafs-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rtl8812au-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sysdig-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v4l2loopback-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/24");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-0.8-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-debugsource-0.8-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-default-0.8_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-default-debuginfo-0.8_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-preempt-0.8_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bbswitch-kmp-preempt-debuginfo-0.8_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-debuginfo-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-debugsource-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-devel-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-eppic-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-eppic-debuginfo-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-gcore-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-gcore-debuginfo-7.2.8-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-default-7.2.8_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-default-debuginfo-7.2.8_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-preempt-7.2.8_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"crash-kmp-preempt-debuginfo-7.2.8_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-debuginfo-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-debugsource-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-devel-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-devel-debuginfo-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-examples-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-examples-debuginfo-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-default-19.11.1_k5.3.18_lp152.36-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-default-debuginfo-19.11.1_k5.3.18_lp152.36-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-preempt-19.11.1_k5.3.18_lp152.36-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-kmp-preempt-debuginfo-19.11.1_k5.3.18_lp152.36-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-tools-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dpdk-tools-debuginfo-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-9.0.22~1+git.fe2b5983-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-debugsource-9.0.22~1+git.fe2b5983-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-default-9.0.22~1+git.fe2b5983_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-default-debuginfo-9.0.22~1+git.fe2b5983_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-preempt-9.0.22~1+git.fe2b5983_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"drbd-kmp-preempt-debuginfo-9.0.22~1+git.fe2b5983_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hdjmod-debugsource-1.28-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hdjmod-kmp-default-1.28_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hdjmod-kmp-default-debuginfo-1.28_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hdjmod-kmp-preempt-1.28_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hdjmod-kmp-preempt-debuginfo-1.28_k5.3.18_lp152.36-lp152.6.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdpdk-20_0-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdpdk-20_0-debuginfo-19.11.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-1.62-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-debuginfo-1.62-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-debugsource-1.62-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-default-1.62_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-default-debuginfo-1.62_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-preempt-1.62_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mhvtl-kmp-preempt-debuginfo-1.62_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-authlibs-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-authlibs-debuginfo-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-authlibs-devel-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-client-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-client-debuginfo-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-debuginfo-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-debugsource-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-devel-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-devel-debuginfo-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-fuse_client-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-fuse_client-debuginfo-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kernel-source-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-default-1.8.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-default-debuginfo-1.8.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-preempt-1.8.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-kmp-preempt-debuginfo-1.8.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-server-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openafs-server-debuginfo-1.8.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-0.44-lp152.4.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-debuginfo-0.44-lp152.4.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-debugsource-0.44-lp152.4.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-default-0.44_k5.3.18_lp152.36-lp152.4.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-default-debuginfo-0.44_k5.3.18_lp152.36-lp152.4.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-preempt-0.44_k5.3.18_lp152.36-lp152.4.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcfclock-kmp-preempt-debuginfo-0.44_k5.3.18_lp152.36-lp152.4.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-debuginfo-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-5.6.4.2+git20200318.49e98ff-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-debugsource-5.6.4.2+git20200318.49e98ff-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-default-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-default-debuginfo-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-preempt-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rtl8812au-kmp-preempt-debuginfo-5.6.4.2+git20200318.49e98ff_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-0.26.5-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-debuginfo-0.26.5-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-debugsource-0.26.5-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-default-0.26.5_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-default-debuginfo-0.26.5_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-preempt-0.26.5_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"sysdig-kmp-preempt-debuginfo-0.26.5_k5.3.18_lp152.36-lp152.3.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-debugsource-0.12.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-default-0.12.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-default-debuginfo-0.12.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-preempt-0.12.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-kmp-preempt-debuginfo-0.12.5_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"v4l2loopback-utils-0.12.5-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-default-20200106_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-default-debuginfo-20200106_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-preempt-20200106_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vhba-kmp-preempt-debuginfo-20200106_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debuginfo-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debugsource-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-devel-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-desktop-icons-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-source-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-debuginfo-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-debuginfo-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-host-source-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-6.1.10_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-debuginfo-6.1.10_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-6.1.10_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-debuginfo-6.1.10_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-debuginfo-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-vnc-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-debuginfo-6.1.10-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-3.9-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-debuginfo-3.9-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-default-3.9_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-default-debuginfo-3.9_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-preempt-3.9_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xtables-addons-kmp-preempt-debuginfo-3.9_k5.3.18_lp152.36-lp152.2.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bbswitch / bbswitch-debugsource / bbswitch-kmp-default / etc");
}
