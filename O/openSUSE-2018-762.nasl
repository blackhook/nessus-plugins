#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-762.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111414);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000200", "CVE-2018-1000204", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-10323", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-1094", "CVE-2018-1108", "CVE-2018-1118", "CVE-2018-1120", "CVE-2018-1130", "CVE-2018-12233", "CVE-2018-13053", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-5803", "CVE-2018-5848", "CVE-2018-7492", "CVE-2018-8781", "CVE-2018-9385");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"IAVA", value:"2018-A-0174");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-762) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-762 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2018-13406: An integer overflow in the
    uvesafb_setcmap function could have result in local
    attackers being able to crash the kernel or potentially
    elevate privileges because kmalloc_array is not used
    (bnc#1100418)

  - CVE-2018-13053: The alarm_timer_nsleep function had an
    integer overflow via a large relative timeout because
    ktime_add_safe was not used (bnc#1099924)

  - CVE-2018-9385: Prevent overread of the 'driver_override'
    buffer (bsc#1100491)

  - CVE-2018-13405: The inode_init_owner function allowed
    local users to create files with an unintended group
    ownership allowing attackers to escalate privileges by
    making a plain file executable and SGID (bnc#1100416)

  - CVE-2017-5753: Systems with microprocessors utilizing
    speculative execution and branch prediction may have
    allowed unauthorized disclosure of information to an
    attacker with local user access via a side-channel
    analysis (bsc#1068032).

  - CVE-2018-1118: Linux kernel vhost did not properly
    initialize memory in messages passed between virtual
    guests and the host operating system. This could have
    allowed local privileged users to read some kernel
    memory contents when reading from the /dev/vhost-net
    device file (bsc#1092472).

  - CVE-2018-12233: A memory corruption bug in JFS could
    have been triggered by calling setxattr twice with two
    different extended attribute names on the same file.
    This vulnerability could be triggered by an unprivileged
    user with the ability to create files and execute
    programs (bsc#1097234)

  - CVE-2018-5848: In the function wmi_set_ie(), the length
    validation code did not handle unsigned integer overflow
    properly. As a result, a large value of the 'ie_len'
    argument could have caused a buffer overflow
    (bnc#1097356)

  - CVE-2018-1000204: Prevent infoleak caused by incorrect
    handling of the SG_IO ioctl (bsc#1096728)

  - CVE-2018-1120: By mmap()ing a FUSE-backed file onto a
    process's memory containing command line arguments (or
    environment strings), an attacker could have caused
    utilities from psutils or procps (such as ps, w) to
    block indefinitely (denial of service) or for some
    controlled time (as a synchronization primitive for
    other attacks) (bsc#1093158).

  - CVE-2018-1094: The ext4_fill_super function did not
    always initialize the crc32c checksum driver, which
    allowed attackers to cause a denial of service
    (ext4_xattr_inode_hash NULL pointer dereference and
    system crash) via a crafted ext4 image (bsc#1087007).

  - CVE-2018-1092: The ext4_iget function mishandled the
    case of a root directory with a zero i_links_count,
    which allowed attackers to cause a denial of service
    (ext4_process_freed_data NULL pointer dereference and
    OOPS) via a crafted ext4 image (bsc#1087012).

  - CVE-2018-1093: The ext4_valid_block_bitmap function
    allowed attackers to cause a denial of service
    (out-of-bounds read and system crash) via a crafted ext4
    image because balloc.c and ialloc.c do not validate
    bitmap block numbers (bsc#1087095).

  - CVE-2018-1000200: Prevent NULL pointer dereference which
    could have resulted in an out of memory (OOM) killing of
    large mlocked processes (bsc#1090150).

  - CVE-2018-1130: NULL pointer dereference in
    dccp_write_xmit() function that allowed a local user to
    cause a denial of service by a number of certain crafted
    system calls (bsc#1092904)

  - CVE-2018-5803: Prevent error in the '_sctp_make_chunk()'
    function when handling SCTP packets length that could
    have been exploited to cause a kernel crash
    (bnc#1083900)

  - CVE-2018-7492: Prevent NULL pointer dereference in the
    net/rds/rdma.c __rds_rdma_map() function that allowed
    local attackers to cause a system panic and a
    denial-of-service, related to RDS_GET_MR and
    RDS_GET_MR_FOR_DEST (bsc#1082962)

  - CVE-2018-1108: Prevent weakness in the implementation of
    random seed data. Programs, early in the boot sequence,
    could have used the data allocated for the seed
    (bsc#1090818).

  - CVE-2018-10323: The xfs_bmap_extents_to_btree function
    allowed local users to cause a denial of service
    (xfs_bmapi_write NULL pointer dereference) via a crafted
    xfs image (bsc#1090717).

  - CVE-2018-8781: The udl_fb_mmap function had an
    integer-overflow vulnerability allowing local users with
    access to the udldrmfb driver to obtain full read and
    write permissions on kernel physical pages, resulting in
    a code execution in kernel space (bsc#1090643)

  - CVE-2018-10124: The kill_something_info function in
    kernel/signal.c might have allowed local users to cause
    a denial of service via an INT_MIN argument
    (bnc#1089752)

  - CVE-2018-10087: The kernel_wait4 function in
    kernel/exit.c might have allowed local users to cause a
    denial of service by triggering an attempted use of the

-INT_MIN value (bnc#1089608)

  - CVE-2017-5715: Prevent unauthorized disclosure of
    information to an attacker with local user access caused
    by speculative execution and indirect branch prediction
    (bsc#1068032)

The following non-security bugs were fixed :

  - 1wire: family module autoload fails because of
    upper/lower case mismatch (bsc#1051510).

  - 8021q: fix a memory leak for VLAN 0 device
    (networking-stable-18_01_12).

  - 8139too: Use disable_irq_nosync() in
    rtl8139_poll_controller() (networking-stable-18_05_15).

  - 8139too: revisit napi_complete_done() usage
    (networking-stable-17_10_09).

  - 9p/trans_virtio: discard zero-length reply
    (bsc#1052766).

  - ACPI / APEI: Replace ioremap_page_range() with fixmap
    (bsc#1051510).

  - ACPI / LPSS: Add missing prv_offset setting for byt/cht
    PWM devices (bsc#1051510).

  - ACPI / NUMA: ia64: Parse all entries of SRAT memory
    affinity table (bnc#1088796, ).

  - ACPI / bus: Do not call _STA on battery devices with
    unmet dependencies (bsc#1051510).

  - ACPI / button: make module loadable when booted in
    non-ACPI mode (bsc#1051510).

  - ACPI / hotplug / PCI: Check presence of slot itself in
    get_slot_status() (bsc#1051510).

  - ACPI / scan: Initialize watchdog before PNP
    (bsc#1073960).

  - ACPI / scan: Send change uevent with offine
    environmental data (bsc#1082485).

  - ACPI / scan: Use acpi_bus_get_status() to initialize
    ACPI_TYPE_DEVICE devs (bsc#1051510).

  - ACPI / video: Add quirk to force acpi-video backlight on
    Samsung 670Z5E (bsc#1051510).

  - ACPI / video: Default lcd_only to true on Win8-ready and
    newer machines (bsc#1051510).

  - ACPI / video: Only default only_lcd to true on
    Win8-ready _desktops_ (bsc#1051510).

  - ACPI / watchdog: Prefer iTCO_wdt on Lenovo Z50-70
    (bsc#1051510).

  - ACPI / watchdog: properly initialize resources
    (bsc#1051510).

  - ACPI: EC: Fix debugfs_create_*() usage (bsc#1051510).

  - ACPI: acpi_pad: Fix memory leak in power saving threads
    (bsc#1051510).

  - ACPI: processor_perflib: Do not send _PPC change
    notification if not ready (bsc#1051510).

  - ACPI: sysfs: Make ACPI GPE mask kernel parameter cover
    all GPEs (bsc#1051510).

  - ACPICA: ACPI 6.0A: Changes to the NFIT ACPI table
    (bsc#1091424).

  - ACPICA: Events: add a return on failure from
    acpi_hw_register_read (bsc#1051510).

  - ACPICA: Fix memory leak on unusual memory leak
    (bsc#1051510).

  - ACPICA: acpi: acpica: fix acpi operand cache leak in
    nseval.c (bsc#1051510).

  - ALSA: aloop: Add missing cable lock to ctl API callbacks
    (bsc#1051510).

  - ALSA: aloop: Mark paused device as inactive
    (bsc#1051510).

  - ALSA: asihpi: Hardening for potential Spectre v1
    (bsc#1051510).

  - ALSA: caiaq: Add yet more sanity checks for invalid EPs
    (bsc#1051510).

  - ALSA: control: Hardening for potential Spectre v1
    (bsc#1051510).

  - ALSA: control: fix a redundant-copy issue (bsc#1051510).

  - ALSA: core: Report audio_tstamp in snd_pcm_sync_ptr
    (bsc#1051510).

  - ALSA: dice: fix OUI for TC group (bsc#1051510).

  - ALSA: dice: fix error path to destroy initialized stream
    data (bsc#1051510).

  - ALSA: dice: fix kernel NULL pointer dereference due to
    invalid calculation for array index (bsc#1051510).

  - ALSA: emu10k1: Fix kABI breakage (bsc#1093027).

  - ALSA: emu10k1: add a IOMMU workaround (bsc#1093027).

  - ALSA: emu10k1: add optional debug printouts with DMA
    addresses (bsc#1093027).

  - ALSA: emu10k1: make sure synth DMA pages are allocated
    with DMA functions (bsc#1093027).

  - ALSA: emu10k1: remove reserved_page (bsc#1093027).

  - ALSA: emu10k1: use dma_set_mask_and_coherent()
    (bsc#1093027).

  - ALSA: hda - Fix incorrect usage of IS_REACHABLE()
    (bsc#1051510).

  - ALSA: hda - Handle kzalloc() failure in
    snd_hda_attach_pcm_stream() (bsc#1051510).

  - ALSA: hda - New VIA controller suppor no-snoop path
    (bsc#1051510).

  - ALSA: hda - Skip jack and others for non-existing PCM
    streams (bsc#1051510).

  - ALSA: hda/ca0132 - use ARRAY_SIZE (bsc#1051510).

  - ALSA: hda/ca0132: Add DSP Volume set and New mixers for
    SBZ + R3Di (bsc#1096696).

  - ALSA: hda/ca0132: Add PCI region2 iomap for SBZ
    (bsc#1096696).

  - ALSA: hda/ca0132: Add dsp setup + gpio functions for
    r3di (bsc#1096696).

  - ALSA: hda/ca0132: Add extra exit functions for R3Di and
    SBZ (bsc#1096696).

  - ALSA: hda/ca0132: Add new control changes for SBZ + R3Di
    (bsc#1096696).

  - ALSA: hda/ca0132: Add pincfg for SBZ + R3Di, add fp hp
    auto-detect (bsc#1096696).

  - ALSA: hda/ca0132: Delete pointless assignments to struct
    auto_pin_cfg fields (bsc#1051510).

  - ALSA: hda/ca0132: Delete redundant UNSOL event requests
    (bsc#1051510).

  - ALSA: hda/ca0132: Do not test for QUIRK_NONE
    (bsc#1051510).

  - ALSA: hda/ca0132: Fix DMic data rate for Alienware M17x
    R4 (bsc#1051510).

  - ALSA: hda/ca0132: R3Di and SBZ quirk entires + alt
    firmware loading (bsc#1096696).

  - ALSA: hda/ca0132: Restore PCM Analog Mic-In2
    (bsc#1051510).

  - ALSA: hda/ca0132: Restore behavior of QUIRK_ALIENWARE
    (bsc#1051510).

  - ALSA: hda/ca0132: add alt_select_in/out for R3Di + SBZ
    (bsc#1096696).

  - ALSA: hda/ca0132: add ca0132_alt_set_vipsource
    (bsc#1096696).

  - ALSA: hda/ca0132: add dsp setup related commands for the
    sbz (bsc#1096696).

  - ALSA: hda/ca0132: add extra init functions for r3di +
    sbz (bsc#1096696).

  - ALSA: hda/ca0132: add the ability to set src_id on scp
    commands (bsc#1096696).

  - ALSA: hda/ca0132: constify parameter table for effects
    (bsc#1096696).

  - ALSA: hda/ca0132: constify read-only members of string
    array (bsc#1096696).

  - ALSA: hda/ca0132: constify templates for control element
    set (bsc#1096696).

  - ALSA: hda/ca0132: fix array_size.cocci warnings
    (bsc#1096696).

  - ALSA: hda/ca0132: fix build failure when a local macro
    is defined (bsc#1051510).

  - ALSA: hda/ca0132: make array ca0132_alt_chmaps static
    (bsc#1051510).

  - ALSA: hda/ca0132: merge strings just for printk
    (bsc#1096696).

  - ALSA: hda/ca0132: update core functions for sbz + r3di
    (bsc#1096696).

  - ALSA: hda/conexant - Add fixup for HP Z2 G4 workstation
    (bsc#1092975).

  - ALSA: hda/conexant - Add hp-mic-fix model string
    (bsc#1092975).

  - ALSA: hda/realtek - Add a quirk for FSC ESPRIMO U9210
    (bsc#1051510).

  - ALSA: hda/realtek - Add shutup hint (bsc#1051510).

  - ALSA: hda/realtek - Add some fixes for ALC233
    (bsc#1051510).

  - ALSA: hda/realtek - Clevo P950ER ALC1220 Fixup
    (bsc#1051510).

  - ALSA: hda/realtek - Enable mic-mute hotkey for several
    Lenovo AIOs (bsc#1051510).

  - ALSA: hda/realtek - Fix pop noise on Lenovo P50 and co
    (bsc#1051510).

  - ALSA: hda/realtek - Fix the problem of two front mics on
    more machines (bsc#1051510).

  - ALSA: hda/realtek - Fixup for HP x360 laptops with BO
    speakers (bsc#1096705).

  - ALSA: hda/realtek - Fixup mute led on HP Spectre x360
    (bsc#1096705).

  - ALSA: hda/realtek - Refactor
    alc269_fixup_hp_mute_led_mic*() (bsc#1096705).

  - ALSA: hda/realtek - Update ALC255 depop optimize
    (bsc#1051510).

  - ALSA: hda/realtek - adjust the location of one mic
    (bsc#1051510).

  - ALSA: hda/realtek - change the location for one of two
    front mics (bsc#1051510).

  - ALSA: hda/realtek - set PINCFG_HEADSET_MIC to
    parse_flags (bsc#1051510).

  - ALSA: hda: Add ASRock H81M-HDS to the power_save
    blacklist (bsc#1051510).

  - ALSA: hda: Add Clevo W35xSS_370SS to the power_save
    blacklist (bsc#1051510).

  - ALSA: hda: Add Gigabyte P55A-UD3 and Z87-D3HP to the
    power_save blacklist (bsc#1051510).

  - ALSA: hda: Add Icelake PCI ID (bsc#1051510).

  - ALSA: hda: Add Intel NUC5i7RY to the power_save
    blacklist (bsc#1051510).

  - ALSA: hda: Add Intel NUC7i3BNB to the power_save
    blacklist (bsc#1051510).

  - ALSA: hda: Add Lenovo C50 All in one to the power_save
    blacklist (bsc#1051510).

  - ALSA: hda: Hardening for potential Spectre v1
    (bsc#1051510).

  - ALSA: hda: add dock and led support for HP EliteBook 830
    G5 (bsc#1051510).

  - ALSA: hda: add dock and led support for HP ProBook 640
    G4 (bsc#1051510).

  - ALSA: hdspm: Hardening for potential Spectre v1
    (bsc#1051510).

  - ALSA: hiface: Add sanity checks for invalid EPs
    (bsc#1051510).

  - ALSA: line6: Add yet more sanity checks for invalid EPs
    (bsc#1051510).

  - ALSA: line6: Use correct endpoint type for midi output
    (bsc#1051510).

  - ALSA: line6: add support for POD HD DESKTOP
    (bsc#1051510).

  - ALSA: line6: add support for POD HD500X (bsc#1051510).

  - ALSA: line6: remove unnecessary initialization to
    PODHD500X (bsc#1051510).

  - ALSA: opl3: Hardening for potential Spectre v1
    (bsc#1051510).

  - ALSA: pcm: Avoid potential races between OSS ioctls and
    read/write (bsc#1051510).

  - ALSA: pcm: Check PCM state at xfern compat ioctl
    (bsc#1051510).

  - ALSA: pcm: Fix UAF at PCM release via PCM timer access
    (bsc#1051510).

  - ALSA: pcm: Fix endless loop for XRUN recovery in OSS
    emulation (bsc#1051510).

  - ALSA: pcm: Fix mutex unbalance in OSS emulation ioctls
    (bsc#1051510).

  - ALSA: pcm: Return -EBUSY for OSS ioctls changing busy
    streams (bsc#1051510).

  - ALSA: pcm: potential uninitialized return values
    (bsc#1051510).

  - ALSA: rawmidi: Fix missing input substream checks in
    compat ioctls (bsc#1051510).

  - ALSA: rme9652: Hardening for potential Spectre v1
    (bsc#1051510).

  - ALSA: seq: Fix UBSAN warning at
    SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT ioctl (bsc#1051510).

  - ALSA: seq: Fix races at MIDI encoding in
    snd_virmidi_output_trigger() (bsc#1051510).

  - ALSA: seq: oss: Fix unbalanced use lock for synth MIDI
    device (bsc#1051510).

  - ALSA: seq: oss: Hardening for potential Spectre v1
    (bsc#1051510).

  - ALSA: timer: Fix UBSAN warning at
    SNDRV_TIMER_IOCTL_NEXT_DEVICE ioctl (bsc#1051510).

  - ALSA: timer: Fix pause event notification (bsc#1051510).

  - ALSA: usb-audio: Add 'Keep Interface' control
    (bsc#1089467).

  - ALSA: usb-audio: Add a quirk for Nura's first gen
    headset (bsc#1051510).

  - ALSA: usb-audio: Add keep_iface flag (bsc#1089467).

  - ALSA: usb-audio: Add native DSD support for Luxman DA-06
    (bsc#1051510).

  - ALSA: usb-audio: Add native DSD support for Mytek DACs
    (bsc#1051510).

  - ALSA: usb-audio: Add native DSD support for TEAC UD-301
    (bsc#1051510).

  - ALSA: usb-audio: Add sample rate quirk for Plantronics
    C310/C520-M (bsc#1051510).

  - ALSA: usb-audio: Add sample rate quirk for Plantronics
    P610 (bsc#1051510).

  - ALSA: usb-audio: Add sanity checks for invalid EPs
    (bsc#1051510).

  - ALSA: usb-audio: Allow to override the longname string
    (bsc#1091678).

  - ALSA: usb-audio: Apply vendor ID matching for sample
    rate quirk (bsc#1051510).

  - ALSA: usb-audio: Avoid superfluous usb_set_interface()
    calls (bsc#1089467).

  - ALSA: usb-audio: Change the semantics of the enable
    option (bsc#1051510).

  - ALSA: usb-audio: Disable the quirk for Nura headset
    (bsc#1051510).

  - ALSA: usb-audio: FIX native DSD support for TEAC UD-501
    DAC (bsc#1051510).

  - ALSA: usb-audio: Generic DSD detection for XMOS-based
    implementations (bsc#1051510).

  - ALSA: usb-audio: Give proper vendor/product name for
    Dell WD15 Dock (bsc#1091678).

  - ALSA: usb-audio: Initialize Dell Dock playback volumes
    (bsc#1089467).

  - ALSA: usb-audio: Integrate native DSD support for
    ITF-USB based DACs (bsc#1051510).

  - ALSA: usb-audio: Remove explicitly listed Mytek devices
    (bsc#1051510).

  - ALSA: usb-audio: Skip broken EU on Dell dock USB-audio
    (bsc#1090658).

  - ALSA: usb-audio: Support changing input on Sound Blaster
    E1 (bsc#1051510).

  - ALSA: usb-audio: add boot quirk for Axe-Fx III
    (bsc#1051510).

  - ALSA: usb-audio: add more quirks for DSD interfaces
    (bsc#1051510).

  - ALSA: usb-audio: simplify set_sync_ep_implicit_fb_quirk
    (bsc#1051510).

  - ALSA: usb: mixer: volume quirk for CM102-A+/102S+
    (bsc#1051510).

  - ALSA: usx2y: Add sanity checks for invalid EPs
    (bsc#1051510).

  - ALSA: usx2y: Fix invalid stream URBs (bsc#1051510).

  - ALSA: vmaster: Propagate slave error (bsc#1051510).

  - ASoC: Intel: Skylake: Disable clock gating during
    firmware and library download (bsc#1051510).

  - ASoC: Intel: cht_bsw_rt5645: Analog Mic support
    (bsc#1051510).

  - ASoC: Intel: sst: remove redundant variable dma_dev_name
    (bsc#1051510).

  - ASoC: adau17x1: Handling of DSP_RUN register during fw
    setup (bsc#1051510).

  - ASoC: cirrus: i2s: Fix LRCLK configuration
    (bsc#1051510).

  - ASoC: cirrus: i2s: Fix {TX|RX}LinCtrlData setup
    (bsc#1051510).

  - ASoC: cs35l35: Add use_single_rw to regmap config
    (bsc#1051510).

  - ASoC: dapm: delete dapm_kcontrol_data paths list before
    freeing it (bsc#1051510).

  - ASoC: fsl_esai: Fix divisor calculation failure at lower
    ratio (bsc#1051510).

  - ASoC: hdmi-codec: Fix module unloading caused kernel
    crash (bsc#1051510).

  - ASoC: hdmi-codec: fix spelling mistake: 'deteced' ->
    'detected' (bsc#1051510).

  - ASoC: hdmi-codec: remove multi detection support
    (bsc#1051510).

  - ASoC: omap: Remove OMAP_MUX dependency from Nokia N810
    audio support (bsc#1051510).

  - ASoC: rockchip: Fix dai_name for HDMI codec
    (bsc#1051510).

  - ASoC: rockchip: rk3288-hdmi-analog: Select needed codecs
    (bsc#1051510).

  - ASoC: rsnd: mark PM functions __maybe_unused
    (bsc#1051510).

  - ASoC: rt5514: Add the missing register in the readable
    table (bsc#1051510).

  - ASoC: samsung: i2s: Ensure the RCLK rate is properly
    determined (bsc#1051510).

  - ASoC: samsung: odroid: Drop requirement of clocks in the
    sound node (bsc#1051510).

  - ASoC: samsung: odroid: Fix 32000 sample rate handling
    (bsc#1051510).

  - ASoC: samsung: odroid: Fix EPLL frequency values
    (bsc#1051510).

  - ASoC: ssm2602: Replace reg_default_raw with reg_default
    (bsc#1051510).

  - ASoC: topology: Check widget kcontrols before deref
    (bsc#1051510).

  - ASoC: topology: Check widget kcontrols before deref
    (bsc#1051510).

  - ASoC: topology: Fix bugs of freeing soc topology
    (bsc#1051510).

  - ASoC: topology: Fix kcontrol name string handling
    (bsc#1051510).

  - ASoC: topology: create TLV data for dapm widgets
    (bsc#1051510).

  - ASoC: topology: fix some tiny memory leaks
    (bsc#1051510).

  - Bluetooth: Add a new 04ca:3015 QCA_ROME device
    (bsc#1051510).

  - Bluetooth: Apply QCA Rome patches for some ATH3012
    models (bsc#1082504).

  - Bluetooth: Fix missing encryption refresh on Security
    Request (bsc#1051510).

  - Bluetooth: Set HCI_QUIRK_SIMULTANEOUS_DISCOVERY for
    BTUSB_QCA_ROME (bsc#1051510).

  - Bluetooth: btrtl: Fix a error code in rtl_load_config()
    (bsc#1051510).

  - Bluetooth: btusb: Add Dell XPS 13 9360 to
    btusb_needs_reset_resume_table (bsc#1051510).

  - Bluetooth: btusb: Add USB ID 7392:a611 for Edimax
    EW-7611ULB (bsc#1051510).

  - Bluetooth: btusb: Add device ID for RTL8822BE
    (bsc#1051510).

  - Bluetooth: btusb: Only check needs_reset_resume DMI
    table for QCA rome chipsets (bsc#1051510).

  - Bluetooth: btusb: add ID for LiteOn 04ca:3016
    (bsc#1051510).

  - Bluetooth: hci_bcm: Add 6 new ACPI HIDs (bsc#1051510).

  - Bluetooth: hci_bcm: Add active_low irq polarity quirk
    for Asus T100CHI (bsc#1051510).

  - Bluetooth: hci_bcm: Add support for BCM2E72
    (bsc#1051510).

  - Bluetooth: hci_bcm: Add support for MINIX Z83-4 based
    devices (bsc#1051510).

  - Bluetooth: hci_bcm: Fix setting of irq trigger type
    (bsc#1051510).

  - Bluetooth: hci_bcm: Handle empty packet after firmware
    loading (bsc#1051510).

  - Bluetooth: hci_bcm: Make bcm_request_irq fail if no IRQ
    resource (bsc#1051510).

  - Bluetooth: hci_bcm: Remove DMI quirk for the MINIX Z83-4
    (bsc#1051510).

  - Bluetooth: hci_bcm: Treat Interrupt ACPI resources as
    always being active-low (bsc#1051510).

  - Bluetooth: hci_qca: Avoid missing rampatch failure with
    userspace fw loader (bsc#1051510).

  - Btrfs: Fix race condition between delayed refs and
    blockgroup removal (bsc#1086224).

  - Btrfs: Fix wrong first_key parameter in replace_path
    (follow up fix for bsc#1084721).

  - Btrfs: Only check first key for committed tree blocks
    (bsc#1084721).

  - Btrfs: Take trans lock before access running trans in
    check_delayed_ref (bsc#1097105).

  - Btrfs: Validate child tree block's level and first key
    (bsc#1084721).

  - Btrfs: fix copy_items() return value when logging an
    inode (bsc#1097105).

  - Btrfs: fix xattr loss after power failure (bsc#1097105).

  - Btrfs: push relocation recovery into a helper thread
    (bsc#1086467).

  - Btrfs: qgroups, fix rescan worker running races
    (bsc#1091101).

  - Btrfs: return error value if create_io_em failed in
    cow_file_range (bsc#1097105).

  - Btrfs: suspend qgroups during relocation recovery
    (bsc#1086467).

  - Btrfs: use btrfs_op instead of bio_op in
    __btrfs_map_block (bsc#1099918).

  - Btrfs: use spinlock to protect ->caching_block_groups
    list (bsc#1083684).

  - Correct bug reference in the patch (bnc#1095155)

  - Delete
    patches.arch/powerpc64-ftrace-Use-the-generic-version-of
    -ftrace_r.patch (bsc#1088804).

  - Downgrade printk level for MMC SDHCI host version error
    (bsc#1097941).

  - Enable uniput driver (bsc#1092566).

  - Fix copy_in_user() declaration (bsc#1052766).

  - Fix kABI breakage due to acpi_ec gpe field change
    (bsc#1051510).

  - Fix kABI breakage due to snd_usb_audio_quirk
    profile_name addition (bsc#1091678).

  - Fix kABI breakage due to sound/timer.h inclusion
    (bsc#1051510).

  - Fix kABI breakage for iwl_fw_runtime_ops change
    (bsc#1051510).

  - Fix kABI breakage for iwlwifi (bsc#1051510).

  - Fix kABI breakage of iio_buffer (bsc#1051510).

  - Fix kABI breakage with CONFIG_RT_GROUP_SCHED=n
    (bsc#1100734).

  - Fix kABI incompatibility by snd_pcm_oss_runtime.rw_ref
    addition (bsc#1051510).

  - Fix the build error in adau17x1 soc driver (bsc#1051510)

  - Fix the build of da9063_wdt module (bsc#1100843)
    Backport the missing prerequisite commit, move the
    previous fixes into the sorted section and refresh.

  - GFS2: Take inode off order_write list when setting jdata
    flag (bsc#1052766).

  - HID: add backlight level quirk for Asus ROG laptops
    (bsc#1101324).

  - HID: cp2112: fix broken gpio_direction_input callback
    (bsc#1051510).

  - HID: debug: check length before copy_to_user()
    (bsc#1051510).

  - HID: hiddev: fix potential Spectre v1 (bsc#1051510).

  - HID: hidraw: Fix crash on HIDIOCGFEATURE with a
    destroyed device (bsc#1051510).

  - HID: i2c-hid: Fix 'incomplete report' noise
    (bsc#1051510).

  - HID: i2c-hid: fix size check and type usage
    (bsc#1051510).

  - HID: intel-ish-hid: Enable Gemini Lake ish driver
    (bsc#1073765,).

  - HID: intel-ish-hid: use put_device() instead of kfree()
    (bsc#1051510).

  - HID: intel_ish-hid: ipc: register more pm callbacks to
    support hibernation (bsc#1051510).

  - HID: lenovo: Add support for IBM/Lenovo Scrollpoint mice
    (bsc#1051510).

  - HID: roccat: prevent an out of bounds read in
    kovaplus_profile_activated() (bsc#1051510).

  - HID: wacom: Add support for One by Wacom (CTL-472 /
    CTL-672) (bsc#1100633).

  - HID: wacom: Correct logical maximum Y for 2nd-gen Intuos
    Pro large (bsc#1051510).

  - HID: wacom: Correct touch maximum XY of 2nd-gen Intuos
    (bsc#1051510).

  - HID: wacom: EKR: ensure devres groups at higher indexes
    are released (bsc#1051510).

  - HID: wacom: Fix reporting of touch toggle
    (WACOM_HID_WD_MUTE_DEVICE) events (bsc#1051510).

  - HID: wacom: Release device resource data obtained by
    devres_alloc() (bsc#1051510).

  - HID: wacom: bluetooth: send exit report for recent
    Bluetooth devices (bsc#1051510).

  - IB/Hfi1: Read CCE Revision register to verify the device
    is responsive (bsc#1096793 ).

  - IB/core: Generate GID change event regardless of RoCE
    GID table property (bsc#1046306 ).

  - IB/core: Refer to RoCE port property instead of GID
    table property (bsc#1046306 ).

  - IB/cq: Do not force IB_POLL_DIRECT poll context for
    ib_process_cq_direct (bsc#1046306 ).

  - IB/hfi1 Use correct type for num_user_context
    (bsc#1096793 ).

  - IB/hfi1: Add a safe wrapper for _rcd_get_by_index
    (bsc#1096793 ).

  - IB/hfi1: Add tx_opcode_stats like the opcode_stats
    (bsc#1096793 ).

  - IB/hfi1: Complete check for locally terminated smp
    (bsc#1096793 ).

  - IB/hfi1: Compute BTH only for RDMA_WRITE_LAST/SEND_LAST
    packet (bsc#1096793 ).

  - IB/hfi1: Convert PortXmitWait/PortVLXmitWait counters to
    flit times (bsc#1096793 ).

  - IB/hfi1: Create common functions for affinity CPU mask
    operations (bsc#1096793 ).

  - IB/hfi1: Do not allocate PIO send contexts for VNIC
    (bsc#1096793 ).

  - IB/hfi1: Do not modify num_user_contexts module
    parameter (bsc#1096793 ).

  - IB/hfi1: Do not override given pcie_pset value
    (bsc#1096793 ).

  - IB/hfi1: Ensure VL index is within bounds (bsc#1096793
    ).

  - IB/hfi1: Fix NULL pointer dereference when invalid
    num_vls is used (bsc#1060463 ).

  - IB/hfi1: Fix a wrapping test to insure the correct
    timeout (bsc#1096793 ).

  - IB/hfi1: Fix for early release of sdma context
    (bsc#1096793 ).

  - IB/hfi1: Fix handling of FECN marked multicast packet
    (bsc#1060463 ).

  - IB/hfi1: Fix loss of BECN with AHG (bsc#1096793 ).

  - IB/hfi1: Fix memory leak in exception path in
    get_irq_affinity() (bsc#1096793 ).

  - IB/hfi1: Fix serdes loopback set-up (bsc#1096793 ).

  - IB/hfi1: Handle initial value of 0 for CCTI setting
    (bsc#1096793 ).

  - IB/hfi1: Inline common calculation (bsc#1096793 ).

  - IB/hfi1: Insure int mask for in-kernel receive contexts
    is clear (bsc#1096793 ).

  - IB/hfi1: Look up ibport using a pointer in receive path
    (bsc#1096793 ).

  - IB/hfi1: Optimize kthread pointer locking when queuing
    CQ entries (bsc#1096793 ).

  - IB/hfi1: Optimize packet type comparison using 9B and
    bypass code paths (bsc#1096793 ).

  - IB/hfi1: Prevent LNI hang when LCB can't obtain lanes
    (bsc#1096793 ).

  - IB/hfi1: Prohibit invalid Init to Armed state transition
    (bsc#1096793 ).

  - IB/hfi1: Race condition between user notification and
    driver state (bsc#1096793 ).

  - IB/hfi1: Re-order IRQ cleanup to address driver cleanup
    race (bsc#1060463 ).

  - IB/hfi1: Refactor assign_ctxt() IOCTL (bsc#1096793 ).

  - IB/hfi1: Refactor get_base_info (bsc#1096793 ).

  - IB/hfi1: Refactor get_ctxt_info (bsc#1096793 ).

  - IB/hfi1: Refactor get_user() IOCTLs (bsc#1096793 ).

  - IB/hfi1: Refactor hfi_user_exp_rcv_clear() IOCTLs
    (bsc#1096793 ).

  - IB/hfi1: Refactor hfi_user_exp_rcv_invalid() IOCTLs
    (bsc#1096793 ).

  - IB/hfi1: Refactor hfi_user_exp_rcv_setup() IOCTL
    (bsc#1096793 ).

  - IB/hfi1: Remove unused hfi1_cpulist variables
    (bsc#1096793 ).

  - IB/hfi1: Reorder incorrect send context disable
    (bsc#1096793 ).

  - IB/hfi1: Return correct value for device state
    (bsc#1096793 ).

  - IB/hfi1: Send 'reboot' as planned down remote reason
    (bsc#1096793 ).

  - IB/hfi1: Set port number for errorinfo MAD response
    (bsc#1096793 ).

  - IB/hfi1: Show fault stats in both TX and RX directions
    (bsc#1096793 ).

  - IB/hfi1: Update HFI to use the latest PCI API
    (bsc#1096793 ).

  - IB/hfi1: Use after free race condition in send context
    error path (bsc#1096793 ).

  - IB/hfi1: Validate PKEY for incoming GSI MAD packets
    (bsc#1096793 ).

  - IB/ipoib: Avoid memory leak if the SA returns a
    different DGID (bsc#1046307 ).

  - IB/ipoib: Change number of TX wqe to 64 (bsc#1096793 ).

  - IB/ipoib: Fix for notify send CQ failure messages
    (bsc#1096793 ).

  - IB/ipoib: Fix for potential no-carrier state
    (bsc#1046307 ).

  - IB/ipoib: Get rid of the tx_outstanding variable in all
    modes (bsc#1096793 ).

  - IB/ipoib: Use NAPI in UD/TX flows (bsc#1096793 ).

  - IB/mlx4: Fix integer overflow when calculating optimal
    MTT size (bsc#1071218).

  - IB/mlx4: Move mlx4_uverbs_ex_query_device_resp to
    include/uapi/ (bsc#1071218).

  - IB/mlx5: Enable ECN capable bits for UD RoCE v2 QPs
    (bsc#1046305 ).

  - IB/mlx5: Respect new UMR capabilities (bsc#1093205).

  - IB/mlx5: Set the default active rate and width to QDR
    and 4X (bsc#1046305 ).

  - IB/mlx5: Use unlimited rate when static rate is not
    supported (bsc#1046305 ).

  - IB/mlx5:: pr_err() and mlx5_ib_dbg() strings should end
    with newlines (bsc#1093205).

  - IB/rdmavt: Add trace for RNRNAK timer (bsc#1096793 ).

  - IB/rdmavt: Allocate CQ memory on the correct node
    (bsc#1058717 ).

  - IB/rdmavt: No need to cancel RNRNAK retry timer when it
    is running (bsc#1096793 ).

  - IB/rdmavt: Use correct numa node for SRQ allocation
    (bsc#1096793 ).

  - IB/srp: Fix completion vector assignment algorithm
    (bsc#1046306 ).

  - IB/srp: Fix srp_abort() (bsc#1046306 ).

  - IB/srpt: Fix an out-of-bounds stack access in
    srpt_zerolength_write() (bsc#1046306 ).

  - IB/uverbs: Fix validating mandatory attributes
    (bsc#1046306 ).

  - IB/{hfi1, qib}: Add handling of kernel restart
    (bsc#1096793 ).

  - IB/{hfi1, rdmavt}: Fix memory leak in
    hfi1_alloc_devdata() upon failure (bsc#1096793 ).

  - IB/{rdmavt,hfi1}: Change hrtimer add to use pinned
    version (bsc#1096793 ).

  - Input: ALPS - fix TrackStick detection on Thinkpad L570
    and Latitude 7370 (bsc#1051510).

  - Input: atmel_mxt_ts - add touchpad button mapping for
    Samsung Chromebook Pro (bsc#1051510).

  - Input: atmel_mxt_ts - fix the firmware update
    (bsc#1051510).

  - Input: elan_i2c - add ELAN0612 (Lenovo v330 14IKB) ACPI
    ID (bsc#1051510).

  - Input: elan_i2c - add ELAN0618 (Lenovo v330 15IKB) ACPI
    ID (bsc#1051510).

  - Input: elan_i2c_smbus - fix corrupted stack
    (bsc#1051510).

  - Input: elan_i2c_smbus - fix more potential stack-based
    buffer overflows (bsc#1051510).

  - Input: elantech - enable middle button of touchpads on
    ThinkPad P52 (bsc#1051510).

  - Input: elantech - fix V4 report decoding for module with
    middle key (bsc#1051510).

  - Input: goodix - add new ACPI id for GPD Win 2 touch
    screen (bsc#1051510).

  - Input: goodix - disable IRQs while suspended
    (bsc#1051510).

  - Input: i8042 - add Lenovo ThinkPad L460 to i8042 reset
    list (bsc#1051510).

  - Input: i8042 - enable MUX on Sony VAIO VGN-CS series to
    fix touchpad (bsc#1051510).

  - Input: leds - fix out of bound access (bsc#1051510).

  - Input: synaptics - Lenovo Carbon X1 Gen5 (2017) devices
    should use RMI (bsc#1051510).

  - Input: synaptics - Lenovo Thinkpad X1 Carbon G5 (2017)
    with Elantech trackpoints should use RMI (bsc#1051510).

  - Input: synaptics - add Intertouch support on X1 Carbon
    6th and X280 (bsc#1051510).

  - Input: synaptics - add Lenovo 80 series ids to SMBus
    (bsc#1051510).

  - Input: synaptics - reset the ABS_X/Y fuzz after
    initializing MT axes (bsc#1051510).

  - Input: synaptics-rmi4 - fix an unchecked out of memory
    error path (bsc#1051510).

  - Input: synaptics: Add intertouch blacklist for Thinkpad
    Helix (bsc#1090457).

  - Input: xpad - add GPD Win 2 Controller USB IDs
    (bsc#1051510).

  - Input: xpad - fix GPD Win 2 controller name
    (bsc#1051510).

  - Input: xpad - sync supported devices with 360Controller
    (bsc#1051510).

  - Input: xpad - sync supported devices with XBCD
    (bsc#1051510).

  - KABI: hide ftrace_enabled in paca (bsc#1088804).

  - KEYS: DNS: limit the length of option strings
    (networking-stable-18_04_26).

  - KEYS: Use individual pages in big_key for crypto buffers
    (bsc#1051510).

  - KVM: MMU: consider host cache mode in MMIO page check
    (bsc#1087213).

  - KVM: PPC: Book3S HV: Fix ppc_breakpoint_available
    compile error (bsc#1061840).

  - KVM: PPC: Book3S HV: Handle migration with POWER9
    disabled DAWR (bsc#1061840).

  - KVM: PPC: Book3S HV: Return error from h_set_dabr() on
    POWER9 (bsc#1061840).

  - KVM: PPC: Book3S HV: Return error from
    h_set_mode(SET_DAWR) on POWER9 (bsc#1061840).

  - KVM: PPC: Book3S HV: trace_tlbie must not be called in
    realmode (bsc#1061840).

  - KVM: arm64: Fix HYP idmap unmap when using 52bit PA
    (bsc#1089074).

  - MD: Free bioset when md_run fails (bsc#1093023).

  - Move upstreamed ideapad-laptop patch to sorted section
    (bsc#1093035)

  - NET: usb: qmi_wwan: add support for ublox R410M PID
    0x90b2 (bsc#1090888).

  - NFC: fix device-allocation error return (bsc#1051510).

  - NFC: llcp: Limit size of SDP URI (bsc#1051510).

  - NFC: pn533: do not send USB data off of the stack
    (bsc#1051510).

  - NFS: Revert 'NFS: Move the flock open mode check into
    nfs_flock()' (bsc#1098983).

  - NFSv4: Revert commit 5f83d86cf531d ('NFSv4.x: Fix
    wraparound issues..') (git-fixes).

  - PCI/ASPM: Add L1 Substates definitions (bsc#1051510).

  - PCI/ASPM: Calculate LTR_L1.2_THRESHOLD from device
    characteristics (bsc#1051510).

  - PCI/DPC: Do not enable DPC if AER control is not allowed
    by the BIOS (bsc#1093184).

  - PCI/PME: Handle invalid data when reading Root Status
    (bsc#1051510).

  - PCI: Add ACS quirk for Intel 300 series (bsc#1051510).

  - PCI: Add ACS quirk for Intel 7th and 8th Gen mobile
    (bsc#1051510).

  - PCI: Add function 1 DMA alias quirk for Highpoint
    RocketRAID 644L (bsc#1051510).

  - PCI: Add function 1 DMA alias quirk for Marvell 88SE9220
    (bsc#1051510).

  - PCI: Add function 1 DMA alias quirk for Marvell 9128
    (bsc#1051510).

  - PCI: Create SR-IOV virtfn/physfn links before attaching
    driver (bsc#1051510).

  - PCI: Detach driver before procfs and sysfs teardown on
    device remove (bsc#1051510).

  - PCI: Mark Broadcom HT1100 and HT2000 Root Port Extended
    Tags as broken (bsc#1051510).

  - PCI: Remove messages about reassigning resources
    (bsc#1051510).

  - PCI: Restore config space on runtime resume despite
    being unbound (bsc#1051510).

  - PCI: aardvark: Fix PCIe Max Read Request Size setting
    (bsc#1051510).

  - PCI: aardvark: Fix logic in advk_pcie_{rd,wr}_conf()
    (bsc#1051510).

  - PCI: aardvark: Set PIO_ADDR_LS correctly in
    advk_pcie_rd_conf() (bsc#1051510).

  - PCI: aardvark: Use ISR1 instead of ISR0 interrupt in
    legacy irq mode (bsc#1051510).

  - PCI: designware-ep: Fix find_first_zero_bit() usage
    (bsc#1051510).

  - PCI: hv: Fix a __local_bh_enable_ip warning in
    hv_compose_msi_msg() (bnc#1094541).

  - PCI: pciehp: Clear Presence Detect and Data Link Layer
    Status Changed on resume (bsc#1051510).

  - PCI: shpchp: Enable bridge bus mastering if MSI is
    enabled (bsc#1051510).

  - PM / OPP: Add missing of_node_put(np) (bsc#1051510).

  - PM / OPP: Call notifier without holding opp_table->lock
    (bsc#1051510).

  - PM / OPP: Move error message to debug level
    (bsc#1051510).

  - PM / devfreq: Fix potential NULL pointer dereference in
    governor_store (bsc#1051510).

  - PM / s2idle: Clear the events_check_enabled flag
    (bsc#1051510).

  - PM / wakeirq: Fix unbalanced IRQ enable for wakeirq
    (bsc#1051510).

  - PM: docs: Drop an excess character from devices.rst
    (bsc#1051510).

  - Pass x86 as architecture on x86_64 and i386
    (bsc#1093118).

  - RDMA/bnxt_re: Fix broken RoCE driver due to recent L2
    driver changes (bsc#1086283 ).

  - RDMA/bnxt_re: Remove redundant bnxt_qplib_disable_nq()
    call (bsc#1086283 ).

  - RDMA/core: Avoid that ib_drain_qp() triggers an
    out-of-bounds stack access (bsc#1046306 ).

  - RDMA/core: Reduce poll batch for direct cq polling
    (bsc#1046306 ).

  - RDMA/i40iw: Avoid panic when reading back the IRQ
    affinity hint (bsc#1084001).

  - RDMA/mlx4: Fix uABI structure layouts for 32/64 compat
    (bsc#1071218).

  - RDMA/mlx5: Fix crash while accessing garbage pointer and
    freed memory (bsc#1046305 ).

  - RDMA/mlx5: Protect from NULL pointer derefence
    (bsc#1046305 ).

  - RDMA/ocrdma: Fix permissions for OCRDMA_RESET_STATS
    (bsc#1058513 ).

  - RDMA/rxe: Fix an out-of-bounds read (bsc#1050662 ).

  - RDMA/ucma: Allow resolving address w/o specifying source
    address (bsc#1046306 ).

  - RDMA/ucma: Introduce safer rdma_addr_size() variants
    (bsc#1046306 ).

  - RDMAVT: Fix synchronization around percpu_ref
    (bsc#1058717 ).

  - RDS: Check cmsg_len before dereferencing CMSG_DATA
    (networking-stable-17_12_31).

  - Refresh
    patches.suse/btrfs-use-kvzalloc-to-allocate-btrfs_fs_inf
    o.patch - Fixed References (bsc#1062897).

  - Remove the old fallback for iTCO/WDAT conflict
    (bsc#1073960) Now the upstream fix is included, so let's
    rip off the old trickery.

  - Revert 'Bluetooth: btusb: Fix quirk for Atheros
    1525/QCA6174' (bsc#1051510).

  - Revert 'Remove patces for bug 1087405 due to regression'
    This reverts commit
    f91a2ea5192d9e933c41600da5d1543155df381c.

  - Revert 'ath10k: send (re)assoc peer command when NSS
    changed' (bsc#1051510).

  - Revert 'drm/i915/edp: Allow alternate fixed mode for eDP
    if available.' (bsc#1093604).

  - Revert 'kernel-binary: do not package extract-cert when
    not signing modules' This reverts commit
    10a8bc496a553b8069d490a8ae7508bdb19f58d9.

  - Revert 'rt2800: use TXOP_BACKOFF for probe frames'
    (bsc#1051510).

  - Revert 'scsi: core: return BLK_STS_OK for DID_OK in
    __scsi_error_from_host_byte()' (bsc#1099918).

  - Revert 'scsi: make 'state' device attribute pollable'
    (bsc#1085341).

  - USB: Accept bulk endpoints with 1024-byte maxpacket
    (bsc#1092888).

  - USB: serial: pl2303: new device id for Chilitag
    (bsc#1087092).

  - USB: serial: simple: add Motorola Tetra driver
    (bsc#1087092).

  - USB:fix USB3 devices behind USB3 hubs not resuming at
    hibernate thaw (bsc#1090888).

  - Update config files, add CONFIG_EXPOLINE_AUTO=y for
    s390x (bsc#1090098).

  - Update config files: disable CONFIG_RT_GROUP_SCHED again
    (bsc#1100734)

  - Update config files: fix for Cherrytrail devices
    (bsc#1068546)

  - Update for above change
    patches.drivers/0003-md-cluster-Suspend-writes-in-RAID10
    -if-within-range.patch (bsc#1093023).

  - Update
    patches.fixes/vti-fix-use-after-free-in-vti_tunnel_xmit-
    vti6_tnl_x.patch (bsc#1076830
    networking-stable-17_10_09).

  - Update
    patches.suse/ceph-don-t-check-quota-for-snap-inode.patch
    (bsc#1089115).

  - Update
    patches.suse/ceph-fix-root-quota-realm-check.patch
    (bsc#1089115).

  - Update
    patches.suse/ceph-quota-add-counter-for-snaprealms-with-
    quota.patch (bsc#1089115).

  - Update
    patches.suse/ceph-quota-add-initial-infrastructure-to-su
    pport-cephfs-quotas.patch (bsc#1089115).

  - Update
    patches.suse/ceph-quota-cache-inode-pointer-in-ceph_snap
    _realm.patch (bsc#1089115).

  - Update
    patches.suse/ceph-quota-don-t-allow-cross-quota-renames.
    patch (bsc#1089115).

  - Update
    patches.suse/ceph-quota-support-for-ceph-quota-max_bytes
    .patch (bsc#1089115).

  - Update
    patches.suse/ceph-quota-support-for-ceph-quota-max_files
    .patch (bsc#1089115).

  - Update
    patches.suse/ceph-quota-update-mds-when-max_bytes-is-app
    roaching.patch (bsc#1089115).

  - X.509: fix BUG_ON() when hash algorithm is unsupported
    (bsc#1051510).

  - X.509: fix NULL dereference when restricting key with
    unsupported_sig (bsc#1051510).

  - X.509: fix comparisons of ->pkey_algo (bsc#1051510).

  - X.509: reject invalid BIT STRING for subjectPublicKey
    (bsc#1051510).

  - acpi, nfit: quiet invalid block-aperture-region warnings
    (bsc#1091781).

  - acpi, nfit: rework NVDIMM leaf method detection
    (bsc#1091782).

  - acpi: Add helper for deactivating memory region
    (bsc#1100132).

  - acpi: nfit: Add support for detect platform CPU cache
    flush on power loss (bsc#1091424).

  - acpi: nfit: add persistent memory control flag for
    nd_region (bsc#1091424).

  - adding missing rcu_read_unlock in ipxip6_rcv
    (networking-stable-17_12_31).

  - af_netlink: ensure that NLMSG_DONE never fails in dumps
    (networking-stable-17_11_20).

  - afs: Connect up the CB.ProbeUuid (bsc#1052766).

  - afs: Fix missing error handling in afs_write_end()
    (bsc#1052766).

  - allow_unsupported: add module tainting on feature use
    ().

  - amd-xgbe: Add pre/post auto-negotiation phy hooks
    (networking-stable-18_04_26).

  - amd-xgbe: Improve KR auto-negotiation and training
    (networking-stable-18_04_26).

  - amd-xgbe: Only use the SFP supported transceiver signals
    (networking-stable-18_04_26).

  - amd-xgbe: Restore PCI interrupt enablement setting on
    resume (networking-stable-18_03_07).

  - apparmor: fix dangling symlinks to policy rawdata after
    replacement (bsc#1095893).

  - apparmor: fix display of .ns_name for containers
    (bsc#1095893).

  - apparmor: fix logging of the existence test for signals
    (bsc#1095893).

  - apparmor: fix memory leak on buffer on error exit path
    (bsc#1095893).

  - arch/*: Kconfig: fix documentation for NMI watchdog
    (bsc#1099918).

  - arm/arm64: smccc: Add SMCCC-specific return codes
    (bsc#1085308).

  - arm64: Add 'ssbd' command-line option (bsc#1085308).

  - arm64: Add ARCH_WORKAROUND_2 probing (bsc#1085308).

  - arm64: Add per-cpu infrastructure to call
    ARCH_WORKAROUND_2 (bsc#1085308).

  - arm64: Call ARCH_WORKAROUND_2 on transitions between EL0
    and EL1 (bsc#1085308).

  - arm64: Update config files. (bsc#1089762) Set NR_CPUS to
    256.

  - arm64: alternatives: Add dynamic patching feature
    (bsc#1085308).

  - arm64: fix endianness annotation for
    __apply_alternatives()/get_alt_insn() (bsc#1085308).

  - arm64: ssbd: Add global mitigation state accessor
    (bsc#1085308).

  - arm64: ssbd: Add prctl interface for per-thread
    mitigation (bsc#1085308).

  - arm64: ssbd: Introduce thread flag to control userspace
    mitigation (bsc#1085308).

  - arm64: ssbd: Restore mitigation status on CPU resume
    (bsc#1085308).

  - arm64: ssbd: Skip apply_ssbd if not using dynamic
    mitigation (bsc#1085308).

  - arp: fix arp_filter on l3slave devices
    (networking-stable-18_04_10).

  - ath10k: Fix kernel panic while using worker
    (ath10k_sta_rc_update_wk) (bsc#1051510).

  - ath10k: correct target assert problem due to CE5 stuck
    (bsc#1051510).

  - ath10k: search all IEs for variant before falling back
    (bsc#1051510).

  - ath9k: fix crash in spectral scan (bsc#1051510).

  - auxdisplay: fix broken menu (bsc#1051510).

  - auxdisplay: img-ascii-lcd: Only build on archs that have
    IOMEM (bsc#1051510).

  - auxdisplay: img-ascii-lcd: add missing
    MODULE_DESCRIPTION/AUTHOR/LICENSE (bsc#1051510).

  - backlight: as3711_bl: Fix Device Tree node lookup
    (bsc#1051510).

  - backlight: max8925_bl: Fix Device Tree node lookup
    (bsc#1051510).

  - backlight: tdo24m: Fix the SPI CS between transfers
    (bsc#1051510).

  - backlight: tps65217_bl: Fix Device Tree node lookup
    (bsc#1051510).

  - bcache: Add __printf annotation to __bch_check_keys()
    (bsc#1093023).

  - bcache: Annotate switch fall-through (bsc#1093023).

  - bcache: Fix a compiler warning in bcache_device_init()
    (bsc#1093023).

  - bcache: Fix indentation (bsc#1093023).

  - bcache: Fix kernel-doc warnings (bsc#1093023).

  - bcache: Fix, improve efficiency of closure_sync()
    (bsc#1093023).

  - bcache: Reduce the number of sparse complaints about
    lock imbalances (bsc#1093023).

  - bcache: Remove an unused variable (bsc#1093023).

  - bcache: Suppress more warnings about set-but-not-used
    variables (bsc#1093023).

  - bcache: Use PTR_ERR_OR_ZERO() (bsc#1093023).

  - bcache: add CACHE_SET_IO_DISABLE to struct cache_set
    flags (bsc#1093023).

  - bcache: add backing_request_endio() for bi_end_io
    (bsc#1093023).

  - bcache: add io_disable to struct cached_dev
    (bsc#1093023).

  - bcache: add journal statistic (bsc#1093023).

  - bcache: add stop_when_cache_set_failed option to backing
    device (bsc#1093023).

  - bcache: add wait_for_kthread_stop() in
    bch_allocator_thread() (bsc#1093023).

  - bcache: allow quick writeback when backing idle
    (bsc#1093023).

  - bcache: closures: move control bits one bit right
    (bsc#1093023).

  - bcache: comment on direct access to bvec table
    (bsc#1093023).

  - bcache: correct flash only vols (check all uuids)
    (bsc#1093023).

  - bcache: count backing device I/O error for writeback I/O
    (bsc#1093023).

  - bcache: fix cached_dev->count usage for
    bch_cache_set_error() (bsc#1093023).

  - bcache: fix error return value in memory shrink
    (bsc#1093023).

  - bcache: fix for allocator and register thread race
    (bsc#1093023).

  - bcache: fix for data collapse after re-attaching an
    attached device (bsc#1093023).

  - bcache: fix high CPU occupancy during journal
    (bsc#1093023).

  - bcache: fix inaccurate io state for detached bcache
    devices (bsc#1093023).

  - bcache: fix incorrect sysfs output value of strip size
    (bsc#1093023).

  - bcache: fix kcrashes with fio in RAID5 backend dev
    (bsc#1093023).

  - bcache: fix misleading error message in
    bch_count_io_errors() (bsc#1093023).

  - bcache: fix unmatched generic_end_io_acct() and
    generic_start_io_acct() (bsc#1093023).

  - bcache: fix using of loop variable in memory shrink
    (bsc#1093023).

  - bcache: fix writeback target calc on large devices
    (bsc#1093023).

  - bcache: fix wrong return value in bch_debug_init()
    (bsc#1093023).

  - bcache: mark closure_sync() __sched (bsc#1093023).

  - bcache: move closure debug file into debug directory
    (bsc#1093023).

  - bcache: properly set task state in
    bch_writeback_thread() (bsc#1093023).

  - bcache: quit dc->writeback_thread when
    BCACHE_DEV_DETACHING is set (bsc#1093023).

  - bcache: reduce cache_set devices iteration by
    devices_max_used (bsc#1093023).

  - bcache: ret IOERR when read meets metadata error
    (bsc#1093023).

  - bcache: return 0 from bch_debug_init() if
    CONFIG_DEBUG_FS=n (bsc#1093023).

  - bcache: return attach error when no cache set exist
    (bsc#1093023).

  - bcache: segregate flash only volume write streams
    (bsc#1093023).

  - bcache: set CACHE_SET_IO_DISABLE in
    bch_cached_dev_error() (bsc#1093023).

  - bcache: set dc->io_disable to true in
    conditional_stop_bcache_device() (bsc#1093023).

  - bcache: set error_limit correctly (bsc#1093023).

  - bcache: set writeback_rate_update_seconds in range [1,
    60] seconds (bsc#1093023).

  - bcache: stop dc->writeback_rate_update properly
    (bsc#1093023).

  - bcache: stop writeback thread after detaching
    (bsc#1093023).

  - bcache: store disk name in struct cache and struct
    cached_dev (bsc#1093023).

  - bcache: use pr_info() to inform duplicated
    CACHE_SET_IO_DISABLE set (bsc#1093023).

  - bcache: writeback: properly order backing device IO
    (bsc#1093023).

  - bdi: Fix oops in wb_workfn() (bsc#1052766).

  - bdi: wake up concurrent wb_shutdown() callers
    (bsc#1052766).

  - be2net: Fix HW stall issue in Lancer (bsc#1086288 ).

  - be2net: Fix error detection logic for BE3 (bsc#1050252
    ).

  - be2net: Handle transmit completion errors in Lancer
    (bsc#1086288 ).

  - bfq-iosched: ensure to clear bic/bfqq pointers when
    preparing request (bsc#1052766).

  - bfq: Re-enable auto-loading when built as a module
    (bsc#1099918).

  - bio-integrity: move the bio integrity profile check
    earlier in bio_integrity_prep (bsc#1093023).

  - bitmap: fix memset optimization on big-endian systems
    (bsc#1051510).

  - bitops: Introduce assign_bit() (bsc#1093023).

  - blacklist.conf: blacklist further commits not needed
    (bsc#1085933, bsc#1085938, bsc#1085939)

  - blacklist.conf: blacklist stable fix 880cd276dff1 ('mm,
    slab: memcg_link the SLAB's kmem_cache'), bsc#1097471

  - blacklist.conf: blacklist tools specific change
    bsc#1085941

  - blk-mq-debugfs: fix device sched directory for default
    scheduler (bsc#1099918).

  - blk-mq: do not keep offline CPUs mapped to hctx 0
    (bsc#1099918).

  - blk-mq: make sure hctx->next_cpu is set correctly
    (bsc#1099918).

  - blk-mq: make sure that correct hctx->next_cpu is set
    (bsc#1099918).

  - blk-mq: reinit q->tag_set_list entry only after grace
    period (bsc#1099918).

  - blk-mq: simplify queue mapping and schedule with each
    possisble CPU (bsc#1099918).

  - block, bfq: add missing invocations of
    bfqg_stats_update_io_add/remove (bsc#1099918).

  - block, bfq: fix occurrences of request finish method's
    old name (bsc#1099918).

  - block, bfq: put async queues for root bfq groups too
    (bsc#1052766).

  - block/loop: fix deadlock after loop_set_status
    (bsc#1052766).

  - block/swim: Remove extra put_disk() call from error path
    (bsc#1099918).

  - block: Add comment to submit_bio_wait() (bsc#1093023).

  - block: Fix __bio_integrity_endio() documentation
    (bsc#1099918).

  - block: Fix cloning of requests with a special payload
    (bsc#1099918).

  - block: Set BIO_TRACE_COMPLETION on new bio during split
    (bsc#1052766).

  - block: cope with WRITE ZEROES failing in
    blkdev_issue_zeroout() (bsc#1099918).

  - block: factor out __blkdev_issue_zero_pages()
    (bsc#1099918).

  - block: sed-opal: Fix a couple off by one bugs
    (bsc#1099918).

  - bnx2x: Collect the device debug information during Tx
    timeout (bsc#1086323 ).

  - bnx2x: Deprecate pci_get_bus_and_slot() (bsc#1086323 ).

  - bnx2x: Replace doorbell barrier() with wmb()
    (bsc#1086323 ).

  - bnx2x: Use NETIF_F_GRO_HW (bsc#1086323 ).

  - bnx2x: Use pci_ari_enabled() instead of local copy
    (bsc#1086323 ).

  - bnx2x: fix slowpath null crash (bsc#1086323 ).

  - bnx2x: fix spelling mistake: 'registeration' ->
    'registration' (bsc#1086323 ).

  - bnx2x: use the right constant (bsc#1086323 ).

  - bnxt_en: Add BCM5745X NPAR device IDs (bsc#1086282 ).

  - bnxt_en: Add IRQ remapping logic (bsc#1086282 ).

  - bnxt_en: Add TC to hardware QoS queue mapping logic
    (bsc#1086282 ).

  - bnxt_en: Add ULP calls to stop and restart IRQs
    (bsc#1086282 ).

  - bnxt_en: Add cache line size setting to optimize
    performance (bsc#1086282 ).

  - bnxt_en: Add extended port statistics support
    (bsc#1086282 ).

  - bnxt_en: Add support for ndo_set_vf_trust (bsc#1086282
    ).

  - bnxt_en: Add the new firmware API to query hardware
    resources (bsc#1086282 ).

  - bnxt_en: Adjust default rings for multi-port NICs
    (bsc#1086282 ).

  - bnxt_en: Always forward VF MAC address to the PF
    (bsc#1086282 ).

  - bnxt_en: Change IRQ assignment for RDMA driver
    (bsc#1086282 ).

  - bnxt_en: Check max_tx_scheduler_inputs value from
    firmware (bsc#1086282 ).

  - bnxt_en: Check the lengths of encapsulated firmware
    responses (bsc#1086282 ).

  - bnxt_en: Check unsupported speeds in bnxt_update_link()
    on PF only (bsc#1086282 ).

  - bnxt_en: Display function level rx/tx_discard_pkts via
    ethtool (bsc#1086282 ).

  - bnxt_en: Do not allow VF to read EEPROM (bsc#1086282 ).

  - bnxt_en: Do not reserve rings on VF when min rings were
    not provisioned by PF (bsc#1086282 ).

  - bnxt_en: Do not set firmware time from VF driver on
    older firmware (bsc#1086282 ).

  - bnxt_en: Eliminate duplicate barriers on weakly-ordered
    archs (bsc#1086282 ).

  - bnxt_en: Expand bnxt_check_rings() to check all
    resources (bsc#1086282 ).

  - bnxt_en: Fix NULL pointer dereference at bnxt_free_irq()
    (bsc#1086282 ).

  - bnxt_en: Fix ethtool -x crash when device is down
    (bsc#1086282 ).

  - bnxt_en: Fix firmware message delay loop regression
    (bsc#1086282 ).

  - bnxt_en: Fix memory fault in bnxt_ethtool_init()
    (bsc#1050242 ).

  - bnxt_en: Fix regressions when setting up MQPRIO TX rings
    (bsc#1086282 ).

  - bnxt_en: Fix vnic accounting in the bnxt_check_rings()
    path (bsc#1086282 ).

  - bnxt_en: Forward VF MAC address to the PF (bsc#1086282
    ).

  - bnxt_en: Ignore src port field in decap filter nodes
    (bsc#1050242 ).

  - bnxt_en: Implement new method for the PF to assign SRIOV
    resources (bsc#1086282 ).

  - bnxt_en: Implement new method to reserve rings
    (bsc#1086282 ).

  - bnxt_en: Improve resource accounting for SRIOV
    (bsc#1086282 ).

  - bnxt_en: Improve ring allocation logic (bsc#1086282 ).

  - bnxt_en: Improve valid bit checking in firmware response
    message (bsc#1086282 ).

  - bnxt_en: Include additional hardware port statistics in
    ethtool -S (bsc#1086282 ).

  - bnxt_en: Increase RING_IDLE minimum threshold to 50
    (bsc#1086282 ).

  - bnxt_en: Need to include RDMA rings in
    bnxt_check_rings() (bsc#1086282 ).

  - bnxt_en: Pass complete VLAN TCI to the stack
    (bsc#1086282 ).

  - bnxt_en: Read phy eeprom A2h address only when optical
    diagnostics is supported (bsc#1086282 ).

  - bnxt_en: Refactor bnxt_close_nic() (bsc#1086282 ).

  - bnxt_en: Refactor bnxt_need_reserve_rings() (bsc#1086282
    ).

  - bnxt_en: Refactor hardware resource data structures
    (bsc#1086282 ).

  - bnxt_en: Refactor the functions to reserve hardware
    rings (bsc#1086282 ).

  - bnxt_en: Remap TC to hardware queues when configuring
    PFC (bsc#1086282 ).

  - bnxt_en: Reserve RSS and L2 contexts for VF (bsc#1086282
    ).

  - bnxt_en: Reserve completion rings and MSIX for bnxt_re
    RDMA driver (bsc#1086282 ).

  - bnxt_en: Reserve resources for RFS (bsc#1086282 ).

  - bnxt_en: Reserve rings at driver open if none was
    reserved at probe time (bsc#1086282 ).

  - bnxt_en: Reserve rings in bnxt_set_channels() if device
    is down (bsc#1086282 ).

  - bnxt_en: Restore MSIX after disabling SRIOV (bsc#1086282
    ).

  - bnxt_en: Set initial default RX and TX ring numbers the
    same in combined mode (bsc#1086282 ).

  - bnxt_en: Simplify ring alloc/free error messages
    (bsc#1086282 ).

  - bnxt_en: Support max-mtu with VF-reps (bsc#1086282 ).

  - bnxt_en: Update firmware interface to 1.9.0 (bsc#1086282
    ).

  - bnxt_en: Update firmware interface to 1.9.1.15
    (bsc#1086282 ).

  - bnxt_en: Use a dedicated VNIC mode for RDMA (bsc#1086282
    ).

  - bnxt_en: close and open NIC, only when the interface is
    in running state (bsc#1086282 ).

  - bnxt_en: do not allow wildcard matches for L2 flows
    (bsc#1050242 ).

  - bnxt_en: export a common switchdev PARENT_ID for all
    reps of an adapter (bsc#1086282 ).

  - bnxt_en: fix clear flags in ethtool reset handling
    (bsc#1050242 ).

  - bnxt_en: reduce timeout on initial HWRM calls
    (bsc#1086282 ).

  - bonding: discard lowest hash bit for 802.3ad layer3+4
    (networking-stable-17_11_20).

  - bonding: do not set slave_dev npinfo before
    slave_enable_netpoll in bond_enslave
    (networking-stable-18_04_26).

  - bonding: fix the err path for dev hwaddr sync in
    bond_enslave (networking-stable-18_04_10).

  - bonding: move dev_mc_sync after master_upper_dev_link in
    bond_enslave (networking-stable-18_04_10).

  - bonding: process the err returned by dev_set_allmulti
    properly in bond_enslave (networking-stable-18_04_10).

  - bonding: send learning packets for vlans on slave
    (networking-stable-18_05_15).

  - bpf, ppc64: fix out of bounds access in tail call
    (bsc#1083647).

  - bpf, x64: fix memleak when not converging after image
    (bsc#1083647).

  - bpf: add schedule points in percpu arrays management
    (bsc#1083647).

  - bpf: fix bpf_skb_adjust_net/bpf_skb_proto_xlat to deal
    with gso sctp skbs (bsc#1076830).

  - bpf: fix mlock precharge on arraymaps (bsc#1083647).

  - bpf: make bnxt compatible w/ bpf_xdp_adjust_tail
    (bsc#1086282 ).

  - bpf: properly enforce index mask to prevent
    out-of-bounds speculation (bsc#1098425).

  - brcmfmac: Fix check for ISO3166 code (bsc#1051510).

  - brd: fix overflow in __brd_direct_access (bsc#1052766).

  - bridge: check iface upper dev when setting master via
    ioctl (networking-stable-18_05_15).

  - can: af_can: can_pernet_init(): add missing error
    handling for kzalloc returning NULL (bsc#1051510).

  - can: af_can: can_rcv(): replace WARN_ONCE by
    pr_warn_once (bsc#1051510).

  - can: af_can: canfd_rcv(): replace WARN_ONCE by
    pr_warn_once (bsc#1051510).

  - can: c_can: do not indicate triple sampling support for
    D_CAN (bsc#1051510).

  - can: cc770: Fix queue stall and dropped RTR reply
    (bsc#1051510).

  - can: cc770: Fix stalls on rt-linux, remove redundant IRQ
    ack (bsc#1051510).

  - can: cc770: Fix use after free in cc770_tx_interrupt()
    (bsc#1051510).

  - can: ems_usb: cancel urb on -EPIPE and -EPROTO
    (bsc#1051510).

  - can: esd_usb2: Fix can_dlc value for received RTR,
    frames (bsc#1051510).

  - can: esd_usb2: cancel urb on -EPIPE and -EPROTO
    (bsc#1051510).

  - can: flex_can: Correct the checking for frame length in
    flexcan_start_xmit() (bsc#1051510).

  - can: flexcan: fix VF610 state transition issue
    (bsc#1051510).

  - can: flexcan: fix i.MX28 state transition issue
    (bsc#1051510).

  - can: flexcan: fix i.MX6 state transition issue
    (bsc#1051510).

  - can: flexcan: fix p1010 state transition issue
    (bsc#1051510).

  - can: flexcan: fix state transition regression
    (bsc#1051510).

  - can: flexcan: implement error passive state quirk
    (bsc#1051510).

  - can: flexcan: rename legacy error state quirk
    (bsc#1051510).

  - can: gs_usb: fix busy loop if no more TX context is
    available (bsc#1051510).

  - can: gs_usb: fix return value of the 'set_bittiming'
    callback (bsc#1051510).

  - can: hi311x: Acquire SPI lock on ->do_get_berr_counter
    (bsc#1051510).

  - can: hi311x: Work around TX complete interrupt erratum
    (bsc#1051510).

  - can: ifi: Check core revision upon probe (bsc#1051510).

  - can: ifi: Fix transmitter delay calculation
    (bsc#1051510).

  - can: ifi: Repair the error handling (bsc#1051510).

  - can: kvaser_usb: Correct return value in printout
    (bsc#1051510).

  - can: kvaser_usb: Fix comparison bug in
    kvaser_usb_read_bulk_callback() (bsc#1051510).

  - can: kvaser_usb: Ignore CMD_FLUSH_QUEUE_REPLY messages
    (bsc#1051510).

  - can: kvaser_usb: Increase correct stats counter in
    kvaser_usb_rx_can_msg() (bsc#1051510).

  - can: kvaser_usb: cancel urb on -EPIPE and -EPROTO
    (bsc#1051510).

  - can: kvaser_usb: free buf in error paths (bsc#1051510).

  - can: kvaser_usb: ratelimit errors if incomplete messages
    are received (bsc#1051510).

  - can: mcba_usb: cancel urb on -EPROTO (bsc#1051510).

  - can: mcba_usb: fix device disconnect bug (bsc#1051510).

  - can: peak/pci: fix potential bug when probe() fails
    (bsc#1051510).

  - can: peak/pcie_fd: fix echo_skb is occupied! bug
    (bsc#1051510).

  - can: peak/pcie_fd: fix potential bug in restarting tx
    queue (bsc#1051510).

  - can: peak/pcie_fd: remove useless code when interface
    starts (bsc#1051510).

  - can: peak: Add support for new PCIe/M2 CAN FD interfaces
    (bsc#1051510).

  - can: peak: fix potential bug in packet fragmentation
    (bsc#1051510).

  - can: sun4i: fix loopback mode (bsc#1051510).

  - can: sun4i: handle overrun in RX FIFO (bsc#1051510).

  - can: ti_hecc: Fix napi poll return value for repoll
    (bsc#1051510).

  - can: usb_8dev: cancel urb on -EPIPE and -EPROTO
    (bsc#1051510).

  - can: vxcan: improve handling of missing peer name
    attribute (bsc#1051510).

  - cdc_ether: flag the Cinterion AHS8 modem by gemalto as
    WWAN (networking-stable-18_04_13).

  - cdrom: information leak in cdrom_ioctl_media_changed()
    (bsc#1051510).

  - ceph: adding protection for showing cap reservation info
    (bsc#1089115).

  - ceph: always update atime/mtime/ctime for new inode
    (bsc#1089115).

  - ceph: change variable name to follow common rule
    (bsc#1089115).

  - ceph: check if mds create snaprealm when setting quota
    (bsc#1089115).

  - ceph: do not wait on writeback when there is no more
    dirty pages (bsc#1089115).

  - ceph: filter out used flags when printing unused open
    flags (bsc#1089115).

  - ceph: fix alignment of rasize (bsc#1098236).

  - ceph: fix dentry leak in splice_dentry() (bsc#1098236).

  - ceph: fix invalid point dereference for error case in
    mdsc destroy (bsc#1089115).

  - ceph: fix rsize/wsize capping in
    ceph_direct_read_write() (bsc#1089115).

  - ceph: fix st_nlink stat for directories (bsc#1093904).

  - ceph: fix use-after-free in ceph_statfs() (bsc#1098236).

  - ceph: fix wrong check for the case of updating link
    count (bsc#1098236).

  - ceph: keep consistent semantic in fscache related option
    combination (bsc#1089115).

  - ceph: mark the cap cache as unreclaimable (bsc#1089115).

  - ceph: optimize mds session register (bsc#1089115).

  - ceph: optimize memory usage (bsc#1089115).

  - ceph: optimizing cap allocation (bsc#1089115).

  - ceph: optimizing cap reservation (bsc#1089115).

  - ceph: prevent i_version from going back (bsc#1098236).

  - ceph: quota: report root dir quota usage in statfs
    (bsc#1089115).

  - ceph: release unreserved caps if having enough available
    caps (bsc#1089115).

  - ceph: return proper bool type to caller instead of
    pointer (bsc#1089115).

  - ceph: support file lock on directory (bsc#1098236).

  - ceph: use seq_show_option for string type options
    (bsc#1089115).

  - cfg80211: clear wep keys after disconnection
    (bsc#1051510).

  - cfg80211: further limit wiphy names to 64 bytes
    (bsc#1051510).

  - cfg80211: limit wiphy names to 128 bytes (bsc#1051510).

  - cgroup: Fix deadlock in cpu hotplug path (Git-fixes).

  - cgroup: Reinit cgroup_taskset structure before
    cgroup_migrate_execute() returns (Git-fixes).

  - cifs: Check for timeout on Negotiate stage
    (bsc#1091171).

  - cifs: silence compiler warnings showing up with
    gcc-8.0.0 (bsc#1090734).

  - config: arm64: enable Spectre-v4 per-thread mitigation

  - coresight: Fix disabling of CoreSight TPIU
    (bsc#1051510).

  - cpufreq: intel_pstate: Add HWP boost utility and sched
    util hooks (bsc#1066110).

  - cpufreq: intel_pstate: Fix scaling max/min limits with
    Turbo 3.0 (bsc#1051510).

  - cpufreq: intel_pstate: HWP boost performance on IO
    wakeup (bsc#1066110).

  - cpufreq: intel_pstate: New sysfs entry to control HWP
    boost (bsc#1066110).

  - cpufreq: intel_pstate: enable boost for Skylake Xeon
    (bsc#1066110).

  - cpufreq: schedutil: Avoid using invalid next_freq
    (git-fixes).

  - cpuidle: fix broadcast control when broadcast can not be
    entered (Git-fixes).

  - cros_ec: fix nul-termination for firmware build info
    (bsc#1051510).

  - crypto: AF_ALG - remove SGL terminator indicator when
    chaining (bsc#1051510).

  - crypto: aes-generic - build with -Os on gcc-7+
    (bsc#1051510).

  - crypto: aes-generic - fix aes-generic regression on
    powerpc (bsc#1051510).

  - crypto: af_alg - fix possible uninit-value in alg_bind()
    (bsc#1051510).

  - crypto: ahash - Fix early termination in hash walk
    (bsc#1051510).

  - crypto: arm,arm64 - Fix random regeneration of S_shipped
    (bsc#1051510).

  - crypto: atmel-aes - fix the keys zeroing on errors
    (bsc#1051510).

  - crypto: caam - Fix null dereference at error path
    (bsc#1051510).

  - crypto: caam - fix DMA mapping dir for generated IV
    (bsc#1051510).

  - crypto: caam - fix IV DMA mapping and updating
    (bsc#1051510).

  - crypto: caam - fix incorrect define (bsc#1051510).

  - crypto: caam - strip input zeros from RSA input buffer
    (bsc#1051510).

  - crypto: caam/qi - fix IV DMA mapping and updating
    (bsc#1051510).

  - crypto: caam/qi - fix IV DMA mapping and updating
    (bsc#1051510).

  - crypto: cavium - Fix fallout from CONFIG_VMAP_STACK
    (bsc#1089141).

  - crypto: cavium - Fix smp_processor_id() warnings
    (bsc#1089141).

  - crypto: cavium - Fix statistics pending request value
    (bsc#1089141).

  - crypto: cavium - Limit result reading attempts
    (bsc#1089141).

  - crypto: cavium - Prevent division by zero (bsc#1089141).

  - crypto: ccp - Fix sparse, use plain integer as NULL
    pointer (git-fixes 200664d5237f).

  - crypto: drbg - set freed buffers to NULL (bsc#1051510).

  - crypto: lrw - Free rctx->ext with kzfree (bsc#1051510).

  - crypto: omap-sham - fix memleak (bsc#1051510).

  - crypto: qat - remove unused and redundant pointer
    vf_info (bsc#1051510).

  - crypto: sunxi-ss - Add MODULE_ALIAS to sun4i-ss
    (bsc#1051510).

  - crypto: vmx - Remove overly verbose printk from AES XTS
    init (bsc#1051510).

  - crypto: vmx - Remove overly verbose printk from AES init
    routines (bsc#1051510).

  - crypto: x86/cast5-avx - fix ECB encryption when long sg
    follows short one (bsc#1051510).

  - cxgb4: Correct ntuple mask validation for hash filters
    (bsc#1064802 bsc#1066129).

  - cxgb4: fix error return code in adap_init0()
    (bsc#1064802 bsc#1066129).

  - cxgb4: fix offset in collecting TX rate limit info
    (bsc#1073513).

  - cxgb4vf: Fix SGE FL buffer initialization logic for 64K
    pages (bsc#1046542 ).

  - dax, dm: allow device-mapper to operate without dax
    support (bsc#1093023).

  - dax: check for QUEUE_FLAG_DAX in bdev_dax_supported()
    (bsc#1101315).

  - dccp: do not restart ccid2_hc_tx_rto_expire() if sk in
    closed state (networking-stable-18_01_28).

  - dccp: fix tasklet usage (networking-stable-18_05_15).

  - delayacct: Account blkio completion on the correct task
    (bsc#1052766).

  - dell_rbu: make firmware payload memory uncachable
    (bsc#1087978).

  - device-dax: allow MAP_SYNC to succeed (bsc#1052766).

  - devlink: Remove redundant free on error path
    (networking-stable-18_03_28).

  - direct-io: Prevent NULL pointer access in
    submit_page_section (bsc#1052766).

  - disable
    patches.drivers/s390-qeth-use-Read-device-to-query-hyper
    visor-for-MA.patch Backport of mainline commit
    b7493e91c11a ('s390/qeth: use Read device to query
    hypervisor for MAC') changes assigned MAC address (and
    breaks networking) on one of our machines and it's not
    clear which address is actually correct (bsc#1094575).
    Disable the patch for now with a marker so that we
    prevent releasing a maintenance update incompatible with
    GM. Once the bug is resolved, we will either reenable
    the patch or drop it.

  - dlm: fix a clerical error when set SCTP_NODELAY
    (bsc#1091594).

  - dlm: make sctp_connect_to_sock() return in specified
    time (bsc#1080542).

  - dlm: remove O_NONBLOCK flag in sctp_connect_to_sock
    (bsc#1080542).

  - dm btree: fix serious bug in btree_split_beneath()
    (bsc#1093023).

  - dm bufio: add missed destroys of client mutex
    (bsc#1093023).

  - dm bufio: check result of register_shrinker()
    (bsc#1093023).

  - dm bufio: delete outdated comment (bsc#1093023).

  - dm bufio: do not embed a bio in the dm_buffer structure
    (bsc#1093023).

  - dm bufio: eliminate unnecessary labels in
    dm_bufio_client_create() (bsc#1093023).

  - dm bufio: fix buffer alignment (bsc#1093023).

  - dm bufio: fix integer overflow when limiting maximum
    cache size (bsc#1093023).

  - dm bufio: fix shrinker scans when (nr_to_scan lower than
    retain_target) (bsc#1093023).

  - dm bufio: get rid of slab cache name allocations
    (bsc#1093023).

  - dm bufio: move dm-bufio.h to include/linux/
    (bsc#1093023).

  - dm bufio: relax alignment constraint on slab cache
    (bsc#1093023).

  - dm bufio: remove code that merges slab caches
    (bsc#1093023).

  - dm bufio: reorder fields in dm_buffer structure
    (bsc#1093023).

  - dm bufio: support non-power-of-two block sizes
    (bsc#1093023).

  - dm bufio: use REQ_OP_READ and REQ_OP_WRITE
    (bsc#1093023).

  - dm bufio: use slab cache for dm_buffer structure
    allocations (bsc#1093023).

  - dm cache background tracker: limit amount of background
    work that may be issued at once (bsc#1093023).

  - dm cache policy smq: allocate cache blocks in order
    (bsc#1093023).

  - dm cache policy smq: change max background work from
    10240 to 4096 blocks (bsc#1093023).

  - dm cache policy smq: handle races with queuing
    background_work (bsc#1093023).

  - dm cache policy smq: take origin idle status into
    account when queuing writebacks (bsc#1093023).

  - dm cache: convert dm_cache_metadata.ref_count from
    atomic_t to refcount_t (bsc#1093023).

  - dm cache: fix race condition in the writeback mode
    overwrite_bio optimisation (bsc#1093023).

  - dm cache: lift common migration preparation code to
    alloc_migration() (bsc#1093023).

  - dm cache: pass cache structure to mode functions
    (bsc#1093023).

  - dm cache: remove all obsolete writethrough-specific code
    (bsc#1093023).

  - dm cache: remove usused deferred_cells member from
    struct cache (bsc#1093023).

  - dm cache: simplify get_per_bio_data() by removing
    data_size argument (bsc#1093023).

  - dm cache: submit writethrough writes in parallel to
    origin and cache (bsc#1093023).

  - dm crypt: allow unaligned bv_offset (bsc#1093023).

  - dm crypt: fix crash by adding missing check for auth key
    size (bsc#1093023).

  - dm crypt: fix error return code in crypt_ctr()
    (bsc#1093023).

  - dm crypt: fix memory leak in crypt_ctr_cipher_old()
    (bsc#1093023).

  - dm crypt: limit the number of allocated pages
    (bsc#1093023).

  - dm crypt: reject sector_size feature if device length is
    not aligned to it (bsc#1093023).

  - dm crypt: remove BIOSET_NEED_RESCUER flag (bsc#1093023).

  - dm crypt: wipe kernel key copy after IV initialization
    (bsc#1093023).

  - dm flakey: check for null arg_name in parse_features()
    (bsc#1093023).

  - dm integrity: allow unaligned bv_offset (bsc#1093023).

  - dm integrity: count and display checksum failures
    (bsc#1093023).

  - dm integrity: do not check integrity for failed read
    operations (bsc#1093023).

  - dm integrity: do not store cipher request on the stack
    (bsc#1093023).

  - dm integrity: fail early if required HMAC key is not
    available (bsc#1093023).

  - dm integrity: make blk_integrity_profile structure const
    (bsc#1093023).

  - dm integrity: optimize writing dm-bufio buffers that are
    partially changed (bsc#1093023).

  - dm integrity: use init_completion instead of
    COMPLETION_INITIALIZER_ONSTACK (bsc#1093023).

  - dm integrity: use kvfree for kvmalloc'd memory
    (bsc#1099918).

  - dm io: remove BIOSET_NEED_RESCUER flag from bios bioset
    (bsc#1093023).

  - dm ioctl: constify ioctl lookup table (bsc#1093023).

  - dm log writes: add support for DAX (bsc#1093023).

  - dm log writes: add support for inline data buffers
    (bsc#1093023).

  - dm log writes: do not use all the cpu while waiting to
    log blocks (bsc#1093023).

  - dm log writes: fix >512b sectorsize support
    (bsc#1093023).

  - dm log writes: fix max length used for kstrndup
    (bsc#1093023).

  - dm log writes: record metadata flag for better flags
    record (bsc#1093023).

  - dm mpath: fix bio-based multipath queue_if_no_path
    handling (bsc#1099918).

  - dm raid: add component device size checks to avoid
    runtime failure (bsc#1093023).

  - dm raid: avoid passing array_in_sync variable to
    raid_status() callees (bsc#1093023).

  - dm raid: bump target version to reflect numerous fixes
    (bsc#1093023).

  - dm raid: consume sizes after md_finish_reshape()
    completes changing them (bsc#1093023).

  - dm raid: correct resizing state relative to reshape
    space in ctr (bsc#1093023).

  - dm raid: display a consistent copy of the MD status via
    raid_status() (bsc#1093023).

  - dm raid: do not use 'const' in function return
    (bsc#1099918).

  - dm raid: ensure 'a' chars during reshape (bsc#1093023).

  - dm raid: fix deadlock caused by premature
    md_stop_writes() (bsc#1093023).

  - dm raid: fix incorrect status output at the end of a
    'recover' process (bsc#1093023).

  - dm raid: fix incorrect sync_ratio when degraded
    (bsc#1093023).

  - dm raid: fix nosync status (bsc#1093023).

  - dm raid: fix panic when attempting to force a raid to
    sync (bsc#1093023).

  - dm raid: fix parse_raid_params() variable range issue
    (bsc#1093023).

  - dm raid: fix raid set size revalidation (bsc#1093023).

  - dm raid: fix raid_resume() to keep raid set frozen as
    needed (bsc#1093023).

  - dm raid: fix rs_get_progress() synchronization
    state/ratio (bsc#1093023).

  - dm raid: make raid_sets symbol static (bsc#1093023).

  - dm raid: simplify rs_get_progress() (bsc#1093023).

  - dm raid: small cleanup and remove unsed 'struct
    raid_set' member (bsc#1093023).

  - dm raid: stop keeping raid set frozen altogether
    (bsc#1093023).

  - dm raid: use rs_is_raid*() (bsc#1093023).

  - dm raid: validate current raid sets redundancy
    (bsc#1093023).

  - dm rq: do not update rq partially in each ending bio
    (bsc#1093023).

  - dm rq: make dm-sq requeuing behavior consistent with
    dm-mq behavior (bsc#1093023).

  - dm space map metadata: use ARRAY_SIZE (bsc#1093023).

  - dm stripe: get rid of a Variable Length Array (VLA)
    (bsc#1093023).

  - dm table: fix regression from improper
    dm_dev_internal.count refcount_t conversion
    (bsc#1093023).

  - dm thin metadata: THIN_MAX_CONCURRENT_LOCKS should be 6
    (bsc#1093023).

  - dm thin: fix trailing semicolon in
    __remap_and_issue_shared_cell (bsc#1093023).

  - dm zoned: avoid triggering reclaim from inside dmz_map()
    (bsc#1099918).

  - dm zoned: ignore last smaller runt zone (bsc#1093023).

  - dm-crypt: do not clear bvec->bv_page in
    crypt_free_buffer_pages() (bsc#1093023).

  - dm-crypt: do not mess with BIP_BLOCK_INTEGRITY
    (bsc#1093023).

  - dm-raid: fix a race condition in request handling
    (bsc#1093023).

  - dm: backfill missing calls to mutex_destroy()
    (bsc#1093023).

  - dm: clear all discard attributes in queue_limits when
    discards are disabled (bsc#1093023).

  - dm: convert DM printk macros to pr_ level macros
    (bsc#1099918).

  - dm: convert dm_dev_internal.count from atomic_t to
    refcount_t (bsc#1093023).

  - dm: convert table_device.count from atomic_t to
    refcount_t (bsc#1093023).

  - dm: correctly handle chained bios in dec_pending()
    (bsc#1093023).

  - dm: discard support requires all targets in a table
    support discards (bsc#1093023).

  - dm: do not set 'discards_supported' in targets that do
    not need it (bsc#1093023).

  - dm: ensure bio submission follows a depth-first tree
    walk (bsc#1093023).

  - dm: ensure bio-based DM's bioset and io_pool support
    targets' maximum IOs (bsc#1093023).

  - dm: fix __send_changing_extent_only() to send first bio
    and chain remainder (bsc#1093023).

  - dm: fix comment above dm_accept_partial_bio
    (bsc#1093023).

  - dm: fix printk() rate limiting code (bsc#1099918).

  - dm: fix various targets to dm_register_target after
    module __init resources created (bsc#1093023).

  - dm: limit the max bio size as BIO_MAX_PAGES * PAGE_SIZE
    (bsc#1093023).

  - dm: move dm_table_destroy() to same header as
    dm_table_create() (bsc#1093023).

  - dm: remove BIOSET_NEED_RESCUER based dm_offload
    infrastructure (bsc#1093023).

  - dm: remove stale comment blocks (bsc#1093023).

  - dm: remove unused 'num_write_bios' target interface
    (bsc#1093023).

  - dm: remove unused macro DM_MOD_NAME_SIZE (bsc#1093023).

  - dm: rename 'bio' member of dm_io structure to 'orig_bio'
    (bsc#1093023).

  - dm: safely allocate multiple bioset bios (bsc#1093023).

  - dm: set QUEUE_FLAG_DAX accordingly in
    dm_table_set_restrictions() (bsc#1093023).

  - dm: simplify start of block stats accounting for
    bio-based (bsc#1093023).

  - dm: small cleanup in dm_get_md() (bsc#1093023).

  - dm: use bio_split() when splitting out the already
    processed bio (bsc#1099918).

  - dmaengine: at_hdmac: fix potential NULL pointer
    dereference in atc_prep_dma_interleaved (bsc#1051510).

  - dmaengine: at_xdmac: fix rare residue corruption
    (bsc#1051510).

  - dmaengine: dmatest: fix container_of member in
    dmatest_callback (bsc#1051510).

  - dmaengine: dmatest: move callback wait queue to thread
    context (bsc#1051510).

  - dmaengine: dmatest: warn user when dma test times out
    (bsc#1051510).

  - dmaengine: edma: Align the memcpy acnt array size with
    the transfer (bsc#1051510).

  - dmaengine: ioat: Fix error handling path (bsc#1051510).

  - dmaengine: jz4740: disable/unprepare clk if probe fails
    (bsc#1051510).

  - dmaengine: ti-dma-crossbar: Correct am335x/am43xx mux
    value type (bsc#1051510).

  - dmaengine: ti-dma-crossbar: Fix event mapping for
    TPCC_EVT_MUX_60_63 (bsc#1051510).

  - dmaengine: ti-dma-crossbar: Fix possible race condition
    with dma_inuse (bsc#1051510).

  - docs: disable KASLR when debugging kernel (bsc#1051510).

  - dpaa_eth: increment the RX dropped counter when needed
    (networking-stable-18_03_28).

  - dpaa_eth: remove duplicate increment of the tx_errors
    counter (networking-stable-18_03_28).

  - dpaa_eth: remove duplicate initialization
    (networking-stable-18_03_28).

  - drbd: Fix drbd_request_prepare() discard handling
    (bsc#1099918).

  - driver core: Do not ignore class_dir_create_and_add()
    failure (bsc#1051510).

  - driver core: Move device_links_purge() after
    bus_remove_device() (bsc#1099918).

  - drivers/infiniband/core/verbs.c: fix build with
    gcc-4.4.4 (bsc#1046306 ).

  - drivers/infiniband/ulp/srpt/ib_srpt.c: fix build with
    gcc-4.4.4 (bsc#1046306 ).

  - drivers: net: bnx2x: use setup_timer() helper
    (bsc#1086323 ).

  - drm/amd/powerplay: Fix enum mismatch (bsc#1051510).

  - drm/amdgpu/sdma: fix mask in emit_pipeline_sync
    (bsc#1051510).

  - drm/amdgpu/si: implement get/set pcie_lanes asic
    callback (bsc#1051510).

  - drm/amdgpu: Add APU support in vi_set_uvd_clocks
    (bsc#1051510).

  - drm/amdgpu: Add APU support in vi_set_vce_clocks
    (bsc#1051510).

  - drm/amdgpu: Add an ATPX quirk for hybrid laptop
    (bsc#1051510).

  - drm/amdgpu: Fix PCIe lane width calculation
    (bsc#1051510).

  - drm/amdgpu: Fix always_valid bos multiple LRU insertions
    (bsc#1051510).

  - drm/amdgpu: Fix deadlock on runtime suspend
    (bsc#1051510).

  - drm/amdgpu: Use kvmalloc_array for allocating VRAM
    manager nodes array (bsc#1051510).

  - drm/amdgpu: adjust timeout for ib_ring_tests(v2)
    (bsc#1051510).

  - drm/amdgpu: disable GFX ring and disable PQ wptr in
    hw_fini (bsc#1051510).

  - drm/amdgpu: set COMPUTE_PGM_RSRC1 for SGPR/VGPR clearing
    shaders (bsc#1051510).

  - drm/amdkfd: fix clock counter retrieval for node without
    GPU (bsc#1051510).

  - drm/armada: fix leak of crtc structure (bsc#1051510).

  - drm/ast: Fixed 1280x800 Display Issue (bsc#1051510).

  - drm/atmel-hlcdc: check stride values in the first plane
    (bsc#1051510).

  - drm/atomic: Clean old_state/new_state in
    drm_atomic_state_default_clear() (bsc#1051510).

  - drm/atomic: Clean private obj old_state/new_state in
    drm_atomic_state_default_clear() (bsc#1051510).

  - drm/bridge: analogix dp: Fix runtime PM state in
    get_modes() callback (bsc#1051510).

  - drm/bridge: tc358767: do no fail on hi-res displays
    (bsc#1051510).

  - drm/bridge: tc358767: filter out too high modes
    (bsc#1051510).

  - drm/bridge: tc358767: fix 1-lane behavior (bsc#1051510).

  - drm/bridge: tc358767: fix AUXDATAn registers access
    (bsc#1051510).

  - drm/bridge: tc358767: fix DP0_MISC register set
    (bsc#1051510).

  - drm/bridge: tc358767: fix timing calculations
    (bsc#1051510).

  - drm/bridge: vga-dac: Fix edid memory leak (bsc#1051510).

  - drm/dumb-buffers: Integer overflow in
    drm_mode_create_ioctl() (bsc#1051510).

  - drm/exynos/dsi: mask frame-done interrupt (bsc#1051510).

  - drm/exynos: Allow DRM_EXYNOS on s5pv210 (bsc#1051510).

  - drm/exynos: Fix default value for zpos plane property
    (bsc#1051510).

  - drm/exynos: fix comparison to bitshift when dealing with
    a mask (bsc#1051510).

  - drm/exynos: g2d: use monotonic timestamps (bsc#1051510).

  - drm/fsl-dcu: enable IRQ before
    drm_atomic_helper_resume() (bsc#1051510).

  - drm/hisilicon: Ensure LDI regs are properly configured
    (bsc#1051510).

  - drm/i915/audio: Fix audio detection issue on GLK
    (bsc#1051510).

  - drm/i915/audio: set minimum CD clock to twice the BCLK
    (bsc#1095265).

  - drm/i915/bios: filter out invalid DDC pins from VBT
    child devices (bsc#1051510).

  - drm/i915/execlists: Use rmb() to order CSB reads
    (bsc#1051510).

  - drm/i915/gen9: Add WaClearHIZ_WM_CHICKEN3 for bxt and
    glk (bsc#1051510).

  - drm/i915/glk: Add MODULE_FIRMWARE for Geminilake
    (bsc#1095265).

  - drm/i915/gvt: fix memory leak of a cmd_entry struct on
    error exit path (bsc#1051510).

  - drm/i915/gvt: throw error on unhandled vfio ioctls
    (bsc#1051510).

  - drm/i915/lvds: Move acpi lid notification registration
    to registration phase (bsc#1051510).

  - drm/i915/psr: Chase psr.enabled only under the psr.lock
    (bsc#1051510).

  - drm/i915/userptr: reject zero user_size (bsc#1051510).

  - drm/i915: Adjust eDP's logical vco in a reliable place
    (bsc#1095265).

  - drm/i915: Apply batch location restrictions before
    pinning (bsc#1051510).

  - drm/i915: Call i915_perf_fini() on init_hw error unwind
    (bsc#1051510).

  - drm/i915: Disable LVDS on Radiant P845 (bsc#1051510).

  - drm/i915: Do no use kfree() to free a kmem_cache_alloc()
    return value (bsc#1051510).

  - drm/i915: Do not request a bug report for unsafe module
    parameters (bsc#1051510).

  - drm/i915: Enable display WA#1183 from its correct spot
    (bsc#1051510).

  - drm/i915: Enable provoking vertex fix on Gen9 systems
    (bsc#1051510).

  - drm/i915: Fix LSPCON TMDS output buffer enabling from
    low-power state (bsc#1051510).

  - drm/i915: Fix context ban and hang accounting for client
    (bsc#1051510).

  - drm/i915: Fix drm:intel_enable_lvds ERROR message in
    kernel log (bsc#1051510).

  - drm/i915: Remove stale asserts from
    i915_gem_find_active_request() (bsc#1051510).

  - drm/i915: Remove stale asserts from
    i915_gem_find_active_request() (bsc#1051510).

  - drm/i915: Remove unbannable context spam from reset
    (bsc#1051510).

  - drm/i915: Restore planes after load detection
    (bsc#1051510).

  - drm/i915: Restore planes after load detection
    (bsc#1051510).

  - drm/i915: Try GGTT mmapping whole object as partial
    (bsc#1051510).

  - drm/imx: move arming of the vblank event to atomic_flush
    (bsc#1051510).

  - drm/meson: Fix an un-handled error path in
    'meson_drv_bind_master()' (bsc#1051510).

  - drm/meson: Fix some error handling paths in
    'meson_drv_bind_master()' (bsc#1051510).

  - drm/meson: fix vsync buffer update (bsc#1051510).

  - drm/msm/dsi: use correct enum in dsi_get_cmd_fmt
    (bsc#1051510).

  - drm/msm: Fix possible null dereference on failure of
    get_pages() (bsc#1051510).

  - drm/msm: do not deref error pointer in the
    msm_fbdev_create error path (bsc#1100209).

  - drm/msm: fix leak in failed get_pages (bsc#1051510).

  - drm/nouveau/bar/gf100: add config option to limit BAR2
    to 16MiB (bsc#1095094).

  - drm/nouveau/bios/iccsense: rails for power sensors have
    a mask of 0xf8 for version 0x10 (bsc#1095094).

  - drm/nouveau/bios/init: add a new devinit script
    interpreter entry-point (bsc#1095094).

  - drm/nouveau/bios/init: add or/link args separate from
    output path (bsc#1095094).

  - drm/nouveau/bios/init: bump script offset to 32-bits
    (bsc#1095094).

  - drm/nouveau/bios/init: remove internal use of
    nvbios_init.bios (bsc#1095094).

  - drm/nouveau/bios/init: rename 'crtc' to 'head'
    (bsc#1095094).

  - drm/nouveau/bios/init: rename nvbios_init() to
    nvbios_devinit() (bsc#1095094).

  - drm/nouveau/bios/volt: Parse min and max for Version
    0x40 (bsc#1095094).

  - drm/nouveau/bios: Demote missing fp table message to
    NV_DEBUG (bsc#1095094).

  - drm/nouveau/bl: fix backlight regression (bsc#1095094).

  - drm/nouveau/devinit: use new devinit script interpreter
    entry-point (bsc#1095094).

  - drm/nouveau/disp/dp: determine a failsafe link training
    rate (bsc#1095094).

  - drm/nouveau/disp/dp: determine link bandwidth
    requirements from head state (bsc#1095094).

  - drm/nouveau/disp/dp: no need for lt_state except during
    manual link training (bsc#1095094).

  - drm/nouveau/disp/dp: only check for re-train when the
    link is active (bsc#1095094).

  - drm/nouveau/disp/dp: remove DP_PWR method (bsc#1095094).

  - drm/nouveau/disp/dp: store current link configuration in
    nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/dp: train link only when actively
    displaying an image (bsc#1095094).

  - drm/nouveau/disp/dp: use cached link configuration when
    checking link status (bsc#1095094).

  - drm/nouveau/disp/dp: use new devinit script interpreter
    entry-point (bsc#1095094).

  - drm/nouveau/disp/g84-: Extend NVKM HDMI power control
    method to set InfoFrames (bsc#1095094).

  - drm/nouveau/disp/g84-: port OR HDMI control to nvkm_ior
    (bsc#1095094).

  - drm/nouveau/disp/g84-gt200: Use supplied HDMI InfoFrames
    (bsc#1095094).

  - drm/nouveau/disp/g94-: port OR DP drive setting control
    to nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/g94-: port OR DP lane mapping to
    nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/g94-: port OR DP link power control to
    nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/g94-: port OR DP link setup to nvkm_ior
    (bsc#1095094).

  - drm/nouveau/disp/g94-: port OR DP training pattern
    control to nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/gf119-: avoid creating non-existent
    heads (bsc#1095094).

  - drm/nouveau/disp/gf119-: port OR DP VCPI control to
    nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/gf119: Use supplied HDMI InfoFrames
    (bsc#1095094).

  - drm/nouveau/disp/gf119: add missing drive vfunc ptr
    (bsc#1095094).

  - drm/nouveau/disp/gk104-: Use supplied HDMI InfoFrames
    (bsc#1095094).

  - drm/nouveau/disp/gm200-: allow non-identity mapping of
    SOR != macro links (bsc#1095094).

  - drm/nouveau/disp/gt215-: port HDA ELD controls to
    nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/gt215: Use supplied HDMI InfoFrames
    (bsc#1095094).

  - drm/nouveau/disp/nv04: avoid creation of output paths
    (bsc#1095094).

  - drm/nouveau/disp/nv50-: avoid creating ORs that are not
    present on HW (bsc#1095094).

  - drm/nouveau/disp/nv50-: execute supervisor on its own
    workqueue (bsc#1095094).

  - drm/nouveau/disp/nv50-: fetch head/OR state at beginning
    of supervisor (bsc#1095094).

  - drm/nouveau/disp/nv50-: implement a common supervisor
    1.0 (bsc#1095094).

  - drm/nouveau/disp/nv50-: implement a common supervisor
    2.0 (bsc#1095094).

  - drm/nouveau/disp/nv50-: implement a common supervisor
    2.1 (bsc#1095094).

  - drm/nouveau/disp/nv50-: implement a common supervisor
    2.2 (bsc#1095094).

  - drm/nouveau/disp/nv50-: implement a common supervisor
    3.0 (bsc#1095094).

  - drm/nouveau/disp/nv50-: port OR manual sink detection to
    nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/nv50-: port OR power state control to
    nvkm_ior (bsc#1095094).

  - drm/nouveau/disp/nv50-gt21x: remove workaround for
    dp->tmds hotplug issues (bsc#1095094).

  - drm/nouveau/disp: Add mechanism to convert HDMI
    InfoFrames to hardware format (bsc#1095094).

  - drm/nouveau/disp: Silence DCB warnings (bsc#1095094).

  - drm/nouveau/disp: add tv encoders to output resource
    mapping (bsc#1095094).

  - drm/nouveau/disp: common implementation of scanoutpos
    method in nvkm_head (bsc#1095094).

  - drm/nouveau/disp: delay output path / connector
    construction until oneinit() (bsc#1095094).

  - drm/nouveau/disp: fork off some new hw-specific
    implementations (bsc#1095094).

  - drm/nouveau/disp: identity-map display paths to output
    resources (bsc#1095094).

  - drm/nouveau/disp: introduce acquire/release display path
    methods (bsc#1095094).

  - drm/nouveau/disp: introduce input/output resource
    abstraction (bsc#1095094).

  - drm/nouveau/disp: introduce object to track per-head
    functions/state (bsc#1095094).

  - drm/nouveau/disp: move vblank_{get,put} methods into
    nvkm_head (bsc#1095094).

  - drm/nouveau/disp: remove hw-specific customisation of
    output paths (bsc#1095094).

  - drm/nouveau/disp: rename nvkm_output to nvkm_outp
    (bsc#1095094).

  - drm/nouveau/disp: rename nvkm_output_dp to nvkm_dp
    (bsc#1095094).

  - drm/nouveau/disp: s/nvkm_connector/nvkm_conn/
    (bsc#1095094).

  - drm/nouveau/disp: shuffle functions around
    (bsc#1095094).

  - drm/nouveau/falcon: use a more reasonable msgqueue
    timeout value (bsc#1095094).

  - drm/nouveau/fb/gf100-: zero mmu debug buffers
    (bsc#1095094).

  - drm/nouveau/fb/ram/nv40-: use new devinit script
    interpreter entry-point (bsc#1095094).

  - drm/nouveau/fbcon: fix oops without fbdev emulation
    (bsc#1094751).

  - drm/nouveau/hwmon: Add config for all sensors and their
    settings (bsc#1095094).

  - drm/nouveau/hwmon: Add nouveau_hwmon_ops structure with
    .is_visible/.read_string (bsc#1095094).

  - drm/nouveau/hwmon: Change permissions to numeric
    (bsc#1095094).

  - drm/nouveau/hwmon: Remove old code, add .write/.read
    operations (bsc#1095094).

  - drm/nouveau/hwmon: expose the auto_point and pwm_min/max
    attrs (bsc#1095094).

  - drm/nouveau/kms/nv04-nv40: improve overlay error
    detection, fix pitch setting (bsc#1095094).

  - drm/nouveau/kms/nv04-nv40: prevent undisplayable
    framebuffers from creation (bsc#1095094).

  - drm/nouveau/kms/nv04-nv4x: fix exposed format list
    (bsc#1095094).

  - drm/nouveau/kms/nv04: use new devinit script interpreter
    entry-point (bsc#1095094).

  - drm/nouveau/kms/nv10-nv40: add NV21 support to overlay
    (bsc#1095094).

  - drm/nouveau/mc/gf100: add pmu to reset mask
    (bsc#1095094).

  - drm/nouveau/mpeg: print more debug info when rejecting
    dma objects (bsc#1095094).

  - drm/nouveau/pmu/fuc: do not use movw directly anymore
    (bsc#1051510).

  - drm/nouveau/pmu/gt215-: abstract detection of whether
    reset is needed (bsc#1095094).

  - drm/nouveau/pmu/gt215: fix reset (bsc#1095094).

  - drm/nouveau/tegra: Do not leave GPU in reset
    (bsc#1095094).

  - drm/nouveau/tegra: Skip manual unpowergating when not
    necessary (bsc#1095094).

  - drm/nouveau/therm/gm200: Added (bsc#1095094).

  - drm/nouveau/therm: fix spelling mistake on array
    thresolds (bsc#1095094).

  - drm/nouveau/tmr: remove nvkm_timer_alarm_cancel()
    (bsc#1095094).

  - drm/nouveau: Clean up nv50_head_atomic_check_mode() and
    fix blankus calculation (bsc#1095094).

  - drm/nouveau: Convert nouveau to use new iterator macros,
    v2 (bsc#1095094).

  - drm/nouveau: Drop drm_vblank_cleanup (bsc#1095094).

  - drm/nouveau: Enable stereoscopic 3D output over HDMI
    (bsc#1095094).

  - drm/nouveau: Fix deadlock in
    nv50_mstm_register_connector() (bsc#1051510).

  - drm/nouveau: Fix deadlock on runtime suspend
    (bsc#1051510).

  - drm/nouveau: Fix merge commit (bsc#1095094).

  - drm/nouveau: Handle drm_atomic_helper_swap_state failure
    (bsc#1095094).

  - drm/nouveau: Handle frame-packing mode geometry and
    timing effects (bsc#1095094).

  - drm/nouveau: Pass mode-dependent AVI and Vendor HDMI
    InfoFrames to NVKM (bsc#1095094).

  - drm/nouveau: Skip vga_fini on non-PCI device
    (bsc#1095094).

  - drm/nouveau: Use the drm_driver.dumb_destroy default
    (bsc#1095094).

  - drm/nouveau: silence suspend/resume debugging messages
    (bsc#1095094).

  - drm/nouveau: use drm_for_each_connector_iter()
    (bsc#1095094).

  - drm/omap: DMM: Check for DMM readiness after successful
    transaction commit (bsc#1051510).

  - drm/omap: fix possible NULL ref issue in
    tiler_reserve_2d (bsc#1051510).

  - drm/omap: fix uninitialized ret variable (bsc#1051510).

  - drm/omap: handle alloc failures in omap_connector
    (bsc#1051510).

  - drm/omap: silence unititialized variable warning
    (bsc#1051510).

  - drm/panel: simple: Fix the bus format for the Ontat
    panel (bsc#1051510).

  - drm/psr: Fix missed entry in PSR setup time table
    (bsc#1051510).

  - drm/qxl: Call qxl_bo_unref outside atomic context
    (bsc#1051510).

  - drm/radeon: Fix PCIe lane width calculation
    (bsc#1051510).

  - drm/radeon: Fix deadlock on runtime suspend
    (bsc#1051510).

  - drm/radeon: add PX quirk for Asus K73TK (bsc#1051510).

  - drm/radeon: make MacBook Pro d3_delay quirk more generic
    (bsc#1051510).

  - drm/rockchip: Clear all interrupts before requesting the
    IRQ (bsc#1051510).

  - drm/rockchip: Respect page offset for PRIME mmap calls
    (bsc#1051510).

  - drm/rockchip: dw-mipi-dsi: fix possible un-balanced
    runtime PM enable (bsc#1051510).

  - drm/sun4i: Fix dclk_set_phase (bsc#1051510).

  - drm/sun4i: Fix error path handling (bsc#1051510).

  - drm/tegra: Shutdown on driver unbind (bsc#1051510).

  - drm/tilcdc: ensure nonatomic iowrite64 is not used
    (bsc#1051510).

  - drm/vc4: Fix memory leak during BO teardown
    (bsc#1051510).

  - drm/vc4: Fix scaling of uni-planar formats
    (bsc#1051510).

  - drm/virtio: fix vq wait_event condition (bsc#1051510).

  - drm/vmwgfx: Fix 32-bit VMW_PORT_HB_[IN|OUT] macros
    (bsc#1051510).

  - drm/vmwgfx: Fix a buffer object leak (bsc#1051510).

  - drm/vmwgfx: Set dmabuf_size when vmw_dmabuf_init is
    successful (bsc#1051510).

  - drm/vmwgfx: Unpin the screen object backup buffer when
    not used (bsc#1051510).

  - drm: Allow determining if current task is output poll
    worker (bsc#1051510).

  - drm: Match sysfs name in link removal to link creation
    (bsc#1051510).

  - drm: bridge: dw-hdmi: Fix overflow workaround for
    Amlogic Meson GX SoCs (bsc#1051510).

  - drm: nouveau: remove dead code and pointless local lut
    storage (bsc#1095094).

  - drm: rcar-du: lvds: Fix LVDS startup on R-Car Gen2
    (bsc#1051510).

  - drm: rcar-du: lvds: Fix LVDS startup on R-Car Gen3
    (bsc#1051510).

  - drm: set FMODE_UNSIGNED_OFFSET for drm files
    (bsc#1051510).

  - e1000e: Ignore TSYNCRXCTL when getting I219 clock
    attributes (bsc#1075876).

  - eCryptfs: do not pass up plaintext names when using
    filename encryption (bsc#1052766).

  - earlycon: Use a pointer table to fix __earlycon_table
    stride (bsc#1099918).

  - efi/esrt: Use memunmap() instead of kfree() to free the
    remapping (bsc#1051510).

  - emulex/benet: Constify *be_misconfig_evt_port_state
    (bsc#1086288 ).

  - ethernet/broadcom: Use zeroing memory allocator than
    allocator/memset (bsc#1086282 ).

  - ethernet: Use octal not symbolic permissions
    (bsc#1086288 ).

  - ethtool: do not print warning for applications using
    legacy API (networking-stable-18_01_12).

  - etnaviv: fix gem object list corruption (bsc#1051510).

  - etnaviv: fix submit error path (bsc#1051510).

  - ext4: Fix hole length detection in ext4_ind_map_blocks()
    (bsc#1090953).

  - ext4: add bounds checking to ext4_xattr_find_entry()
    (bsc#1052766).

  - ext4: do not update checksum of new initialized bitmaps
    (bsc#1052766).

  - ext4: eliminate sleep from shutdown ioctl (bsc#1052766).

  - ext4: fix hole length detection in ext4_ind_map_blocks()
    (bsc#1090953).

  - ext4: fix offset overflow on 32-bit archs in
    ext4_iomap_begin() (bsc#1079747).

  - ext4: fix unsupported feature message formatting
    (bsc#1098435).

  - ext4: move call to ext4_error() into
    ext4_xattr_check_block() (bsc#1052766).

  - ext4: pass -ESHUTDOWN code to jbd2 layer (bsc#1052766).

  - ext4: prevent right-shifting extents beyond
    EXT_MAX_BLOCKS (bsc#1052766).

  - ext4: protect i_disksize update by i_data_sem in direct
    write path (bsc#1052766).

  - ext4: set h_journal if there is a failure starting a
    reserved handle (bsc#1052766).

  - ext4: shutdown should not prevent get_write_access
    (bsc#1052766).

  - extcon: intel-cht-wc: Set direction and drv flags for V5
    boost GPIO (bsc#1051510).

  - f2fs: avoid hungtask when GC encrypted block if io_bits
    is set (bsc#1052766).

  - f2fs: expose some sectors to user in inline data or
    dentry case (bsc#1052766).

  - f2fs: fix a panic caused by NULL flush_cmd_control
    (bsc#1086400).

  - f2fs: fix heap mode to reset it back (bsc#1052766).

  - f2fs: fix to clear CP_TRIMMED_FLAG (bsc#1052766).

  - f2fs: fix to wake up all sleeping flusher (bsc#1099918).

  - fanotify: fix logic of events on child (bsc#1052766).

  - fbdev: controlfb: Add missing modes to fix out of bounds
    access (bsc#1051510).

  - fealnx: Fix building error on MIPS
    (networking-stable-17_11_20).

  - fib_semantics: Do not match route with mismatching
    tclassid (networking-stable-18_03_07).

  - firewire-ohci: work around oversized DMA reads on
    JMicron controllers (bsc#1051510).

  - firmware: add helper to unregister pm ops (bsc#1085937).

  - firmware: always enable the reboot notifier
    (bsc#1085937).

  - firmware: dmi_scan: Fix UUID length safety check
    (bsc#1051510).

  - firmware: dmi_scan: Fix handling of empty DMI strings
    (bsc#1051510).

  - firmware: fix capturing errors on fw_cache_init() on
    early init (bsc#1085937).

  - firmware: fix checking for return values for
    fw_add_devm_name() (bsc#1051510).

  - firmware: fix detecting error on
    register_reboot_notifier() (bsc#1085936).

  - firmware: move kill_requests_without_uevent() up above
    (bsc#1085937).

  - firmware: provide helpers for registering the syfs
    loader (bsc#1085937).

  - firmware: share fw fallback killing on reboot/suspend
    (bsc#1085937).

  - fix kabi breaker in md.h (git-fixes).

  - flow_dissector: properly cap thoff field
    (networking-stable-18_01_28).

  - fs/aio: Add explicit RCU grace period when freeing
    kioctx (bsc#1088722).

  - fs/aio: Use RCU accessors for kioctx_table->table[]
    (bsc#1088722).

  - fs/binfmt_misc.c: do not allow offset overflow
    (bsc#1099142).

  - fs/fat/inode.c: fix sb_rdonly() change (bsc#1052766).

  - fs/reiserfs/journal.c: add missing resierfs_warning()
    arg (bsc#1052766).

  - fs: Teach path_connected to handle nfs filesystems with
    multiple roots (git-fixes).

  - fsnotify: Fix fsnotify_mark_connector race
    (bsc#1052766).

  - fsnotify: Hide kABI changes in fsnotify_mark_connector
    (bsc#1052766).

  - ftrace: Fix selftest goto location on error
    (bsc#1099918).

  - fuse: fix READDIRPLUS skipping an entry (bsc#1088690).

  - geneve: Fix function matching VNI and tunnel ID on
    big-endian (bsc#1051510).

  - geneve: fix fill_info when link down (bsc#1051510).

  - gfs2: Fix debugfs glocks dump (bsc#1052766).

  - gpio: No NULL owner (bsc#1051510).

  - gpio: ath79: add missing MODULE_DESCRIPTION/LICENSE
    (bsc#1051510).

  - gpio: davinci: Assign first bank regs for unbanked case
    (bsc#1051510).

  - gpio: fix 'gpio-line-names' property retrieval
    (bsc#1051510).

  - gpio: fix aspeed_gpio unmask irq (bsc#1051510).

  - gpio: fix error path in lineevent_create (bsc#1051510).

  - gpio: iop: add missing MODULE_DESCRIPTION/AUTHOR/LICENSE
    (bsc#1051510).

  - gpio: label descriptors using the device name
    (bsc#1051510).

  - gpio: stmpe: i2c transfer are forbiden in atomic context
    (bsc#1051510).

  - gpioib: do not free unrequested descriptors
    (bsc#1051510).

  - gpu: ipu-v3: pre: fix device node leak in
    ipu_pre_lookup_by_phandle (bsc#1051510).

  - gpu: ipu-v3: prg: avoid possible array underflow
    (bsc#1051510).

  - gpu: ipu-v3: prg: fix device node leak in
    ipu_prg_lookup_by_phandle (bsc#1051510).

  - hdlc_ppp: carrier detect ok, do not turn off negotiation
    (networking-stable-18_03_07).

  - hv_netvsc: Fix a network regression after ifdown/ifup
    (bsc#1094420).

  - hwmon: (ina2xx) Fix access to uninitialized mutex
    (bsc#1051510).

  - hwmon: (ina2xx) Make calibration register value fixed
    (bsc#1051510).

  - hwmon: (jc42) optionally try to disable the SMBUS
    timeout (bsc#1051510).

  - hwmon: (nct6775) Fix writing pwmX_mode (bsc#1051510).

  - hwmon: (pmbus/adm1275) Accept negative page register
    values (bsc#1051510).

  - hwmon: (pmbus/max8688) Accept negative page register
    values (bsc#1051510).

  - hwtracing: stm: fix build error on some arches
    (bsc#1051510).

  - i2c: designware: fix poll-after-enable regression
    (bsc#1051510).

  - i2c: i801: Restore configuration at shutdown
    (bsc#1051510).

  - i2c: i801: Save register SMBSLVCMD value only once
    (bsc#1051510).

  - i2c: ismt: Separate I2C block read from SMBus block read
    (bsc#1051510).

  - i2c: mv64xxx: Apply errata delay only in standard mode
    (bsc#1051510).

  - i2c: pmcmsp: fix error return from master_xfer
    (bsc#1051510).

  - i2c: pmcmsp: return message count on master_xfer success
    (bsc#1051510).

  - i2c: viperboard: return message count on master_xfer
    success (bsc#1051510).

  - i40e: Close client on suspend and restore client MSIx on
    resume (bsc#1088821).

  - i40e: Do not allow use more TC queue pairs than MSI-X
    vectors exist (bsc#1094978).

  - i40e: Fix attach VF to VM issue (bsc#1056658 bsc#1056662
    ).

  - i40e: Fix the number of queues available to be mapped
    for use (bsc#1094978).

  - i40e: program fragmented IPv4 filter input set
    (bsc#1056658 bsc#1056662 ).

  - i40evf: Do not schedule reset_task when device is being
    removed (bsc#1056658 bsc#1056662 ).

  - i40evf: do not rely on netif_running() outside
    rtnl_lock() (bsc#1056658 bsc#1056662 ).

  - i40evf: ignore link up if not running (bsc#1056658
    bsc#1056662 ).

  - i40iw: Zero-out consumer key on allocate stag for FMR
    (bsc#1058659 ).

  - ibmvnic: Check CRQ command return codes (bsc#1094840).

  - ibmvnic: Clean actual number of RX or TX pools
    (bsc#1092289).

  - ibmvnic: Clear pending interrupt after device reset
    (bsc#1089644).

  - ibmvnic: Create separate initialization routine for
    resets (bsc#1094840).

  - ibmvnic: Define vnic_login_client_data name field as
    unsized array (bsc#1089198).

  - ibmvnic: Do not notify peers on parameter change resets
    (bsc#1089198).

  - ibmvnic: Fix non-fatal firmware error reset
    (bsc#1093990).

  - ibmvnic: Fix partial success login retries
    (bsc#1094840).

  - ibmvnic: Fix statistics buffers memory leak
    (bsc#1093990).

  - ibmvnic: Free coherent DMA memory if FW map failed
    (bsc#1093990).

  - ibmvnic: Handle all login error conditions
    (bsc#1089198).

  - ibmvnic: Handle error case when setting link state
    (bsc#1094840).

  - ibmvnic: Introduce active CRQ state (bsc#1094840).

  - ibmvnic: Introduce hard reset recovery (bsc#1094840).

  - ibmvnic: Mark NAPI flag as disabled when released
    (bsc#1094840).

  - ibmvnic: Only do H_EOI for mobility events
    (bsc#1094356).

  - ibmvnic: Return error code if init interrupted by
    transport event (bsc#1094840).

  - ibmvnic: Set resetting state at earliest possible point
    (bsc#1094840).

  - ide: Make ide_cdrom_prep_fs() initialize the sense
    buffer pointer (bsc#1099918).

  - ide: ide-atapi: fix compile error with defining macro
    DEBUG (bsc#1099918).

  - ide:ide-cd: fix kernel panic resulting from missing
    scsi_req_init (bsc#1099918).

  - idr: fix invalid ptr dereference on item delete
    (bsc#1051510).

  - ieee802154: 6lowpan: fix possible NULL deref in
    lowpan_device_event() (networking-stable-18_03_28).

  - igb: Allow to remove administratively set MAC on VFs
    (bsc#1056651 ).

  - igb: Clear TXSTMP when ptp_tx_work() is timeout
    (bsc#1056651 ).

  - igb: Fix a test with HWTSTAMP_TX_ON (bsc#1056651
    bsc#1056643 ).

  - iio: ABI: Fix name of timestamp sysfs file
    (bsc#1051510).

  - iio: ad7793: Fix the serial interface reset
    (bsc#1051510).

  - iio: ad7793: implement IIO_CHAN_INFO_SAMP_FREQ
    (bsc#1051510).

  - iio: ad_sigma_delta: Implement a dedicated reset
    function (bsc#1051510).

  - iio: adc/accel: Fix up module licenses (bsc#1051510).

  - iio: adc: cpcap: fix incorrect validation (bsc#1051510).

  - iio: adc: mcp320x: Fix oops on module unload
    (bsc#1051510).

  - iio: adc: mcp320x: Fix readout of negative voltages
    (bsc#1051510).

  - iio: adc: meson-saradc: fix the bit_idx of the adc_en
    clock (bsc#1051510).

  - iio: adc: stm32: fix scan of multiple channels with DMA
    (bsc#1051510).

  - iio: adc: ti-ads1015: add 10% to conversion wait time
    (bsc#1051510).

  - iio: adc: twl4030: Disable the vusb3v1 rugulator in the
    error handling path of 'twl4030_madc_probe()'
    (bsc#1051510).

  - iio: adc: twl4030: Fix an error handling path in
    'twl4030_madc_probe()' (bsc#1051510).

  - iio: adis_lib: Initialize trigger before requesting
    interrupt (bsc#1051510).

  - iio: buffer: check if a buffer has been set up when poll
    is called (bsc#1051510).

  - iio: buffer: fix the function signature to match
    implementation (bsc#1051510).

  - iio: core: Return error for failed read_reg
    (bsc#1051510).

  - iio: fix kernel-doc build errors (bsc#1051510).

  - iio: health: max30102: Add power enable parameter to
    get_temp function (bsc#1051510).

  - iio: health: max30102: Temperature should be in milli
    Celsius (bsc#1051510).

  - iio: imu: st_lsm6dsx: fix endianness in
    st_lsm6dsx_read_oneshot() (bsc#1051510).

  - iio: st_pressure: st_accel: Initialise sensor platform
    data properly (bsc#1051510).

  - iio: st_pressure: st_accel: pass correct platform data
    to init (bsc#1051510).

  - iio: trigger: stm32-timer: fix get/set down count
    direction (bsc#1051510).

  - iio: trigger: stm32-timer: fix get/set down count
    direction (bsc#1051510).

  - iio: trigger: stm32-timer: preset shouldn't be buffered
    (bsc#1051510).

  - iio:buffer: make length types match kfifo types
    (bsc#1051510).

  - iio:kfifo_buf: check for uint overflow (bsc#1051510).

  - ima: Fallback to the builtin hash algorithm
    (bsc#1091686).

  - infiniband: drop unknown function from core_priv.h
    (bsc#1046306 ).

  - init: fix false positives in W+X checking (bsc#1093721).

  - initial support (display-only) for GP108 (bsc#1095094).

  - intel_th: Use correct device when freeing buffers
    (bsc#1051510).

  - iommu/amd: Take into account that alloc_dev_data() may
    return NULL (bsc#975772).

  - iommu/vt-d: Clear pasid table entry when memory unbound
    (bsc#1087214).

  - iommu/vt-d: Fix race condition in add_unmap()
    (bsc#1096790, bsc#1097034).

  - iov_iter: fix memory leak in pipe_get_pages_alloc()
    (bsc#1092710).

  - iov_iter: fix return type of __pipe_get_pages()
    (bsc#1092710).

  - ip6_gre: better validate user provided tunnel names
    (networking-stable-18_04_10).

  - ip6_gre: fix device features for ioctl setup
    (networking-stable-17_12_31).

  - ip6_gre: init dev->mtu and dev->hard_header_len
    correctly (networking-stable-18_01_28).

  - ip6_gre: ip6gre_tap device should keep dst
    (networking-stable-17_10_09).

  - ip6_gre: only increase err_count for some certain type
    icmpv6 in ip6gre_err (networking-stable-17_11_14).

  - ip6_gre: skb_push ipv6hdr before packing the header in
    ip6gre_header (networking-stable-17_10_09).

  - ip6_tunnel: better validate user provided tunnel names
    (networking-stable-18_04_10).

  - ip6_tunnel: disable dst caching if tunnel is dual-stack
    (networking-stable-18_01_12).

  - ip6_tunnel: do not allow loading ip6_tunnel if ipv6 is
    disabled in cmdline (networking-stable-17_10_09).

  - ip6_vti: adjust vti mtu according to mtu of lower device
    (bsc#1082869).

  - ip6mr: fix stale iterator (networking-stable-18_02_06).

  - ip6mr: only set ip6mr_table from setsockopt when
    ip6mr_new_table succeeds (git-fixes).

  - ip_gre: fix IFLA_MTU ignored on NEWLINK (bsc#1076830).

  - ip_tunnel: better validate user provided tunnel names
    (networking-stable-18_04_10).

  - ipip: only increase err_count for some certain type icmp
    in ipip_err (networking-stable-17_11_14).

  - ipmi_ssif: Fix kernel panic at msg_done_handler
    (bsc#1088872).

  - ipv4: Fix use-after-free when flushing FIB tables
    (networking-stable-17_12_31).

  - ipv4: Make neigh lookup keys for loopback/point-to-point
    devices be INADDR_ANY (networking-stable-18_01_28).

  - ipv4: fix fnhe usage by non-cached routes
    (networking-stable-18_05_15).

  - ipv4: fix memory leaks in udp_sendmsg, ping_v4_sendmsg
    (networking-stable-18_05_15).

  - ipv4: igmp: guard against silly MTU values
    (bsc#1082869).

  - ipv6 sit: work around bogus gcc-8 -Wrestrict warning
    (networking-stable-18_03_07).

  - ipv6: Fix getsockopt() for sockets with default
    IPV6_AUTOFLOWLABEL (git-fixes).

  - ipv6: add RTA_TABLE and RTA_PREFSRC to rtm_ipv6_policy
    (networking-stable-18_04_26).

  - ipv6: fix access to non-linear packet in
    ndisc_fill_redirect_hdr_option()
    (networking-stable-18_03_28).

  - ipv6: fix udpv6 sendmsg crash caused by too small MTU
    (networking-stable-18_01_28).

  - ipv6: flowlabel: do not leave opt->tot_len with garbage
    (networking-stable-17_11_14).

  - ipv6: mcast: better catch silly mtu values
    (networking-stable-17_12_31).

  - ipv6: old_dport should be a __be16 in
    __ip6_datagram_connect() (networking-stable-18_03_28).

  - ipv6: omit traffic class when calculating flow hash
    (bsc#1095042).

  - ipv6: sit: better validate user provided tunnel names
    (networking-stable-18_04_10).

  - ipv6: sr: fix NULL pointer dereference in
    seg6_do_srh_encap()- v4 pkts (git-fixes).

  - ipv6: sr: fix NULL pointer dereference when setting
    encap source address (networking-stable-18_03_28).

  - ipv6: sr: fix TLVs not being copied using setsockopt
    (networking-stable-18_01_12).

  - ipv6: sr: fix scheduling in RCU when creating seg6
    lwtunnel state (networking-stable-18_03_28).

  - ipv6: sr: fix seg6 encap performances with TSO enabled
    (networking-stable-18_04_10).

  - ipv6: the entire IPv6 header chain must fit the first
    fragment (networking-stable-18_04_10).

  - irqchip/gic-v3-its: Ensure nr_ites >= nr_lpis
    (bsc#1098401).

  - isdn: eicon: fix a missing-check bug (bsc#1051510).

  - iw_cxgb4: Atomically flush per QP HW CQEs (bsc#1046543
    ).

  - iw_cxgb4: Fix an error handling path in
    'c4iw_get_dma_mr()' (bsc#1064802 bsc#1066129).

  - iw_cxgb4: print mapped ports correctly (bsc#1046543 ).

  - iwlmvm: tdls: Check TDLS channel switch support
    (bsc#1051510).

  - iwlwifi: add a bunch of new 9000 PCI IDs (1051510).

  - iwlwifi: add shared clock PHY config flag for some
    devices (bsc#1051510).

  - iwlwifi: avoid collecting firmware dump if not loaded
    (bsc#1051510).

  - iwlwifi: fix non_shared_ant for 9000 devices
    (bsc#1051510).

  - iwlwifi: fw: harden page loading code (bsc#1051510).

  - iwlwifi: mvm: Correctly set IGTK for AP (bsc#1051510).

  - iwlwifi: mvm: Correctly set the tid for mcast queue
    (bsc#1051510).

  - iwlwifi: mvm: Direct multicast frames to the correct
    station (bsc#1051510).

  - iwlwifi: mvm: Fix channel switch for count 0 and 1
    (bsc#1051510).

  - iwlwifi: mvm: Increase session protection time after CS
    (bsc#1051510).

  - iwlwifi: mvm: always init rs with 20mhz bandwidth rates
    (bsc#1051510).

  - iwlwifi: mvm: clear tx queue id when unreserving
    aggregation queue (bsc#1051510).

  - iwlwifi: mvm: do not warn in queue sync on RF-kill
    (bsc#1051510 ).

  - iwlwifi: mvm: fix 'failed to remove key' message
    (bsc#1051510).

  - iwlwifi: mvm: fix IBSS for devices that support station
    type API (bsc#1051510).

  - iwlwifi: mvm: fix TSO with highly fragmented SKBs
    (bsc#1051510).

  - iwlwifi: mvm: fix TX of CCMP 256 (bsc#1051510).

  - iwlwifi: mvm: fix array out of bounds reference
    (bsc#1051510).

  - iwlwifi: mvm: fix assert 0x2B00 on older FWs
    (bsc#1051510).

  - iwlwifi: mvm: fix error checking for multi/broadcast sta
    (bsc#1051510).

  - iwlwifi: mvm: fix race in queue notification wait
    (bsc#1051510).

  - iwlwifi: mvm: fix security bug in PN checking
    (bsc#1051510).

  - iwlwifi: mvm: honor the max_amsdu_subframes limit
    (bsc#1051510).

  - iwlwifi: mvm: make sure internal station has a valid id
    (bsc#1051510).

  - iwlwifi: mvm: remove DQA non-STA client mode special
    case (bsc#1051510 ).

  - iwlwifi: mvm: set the correct tid when we flush the
    MCAST sta (bsc#1051510).

  - iwlwifi: pcie: compare with number of IRQs requested
    for, not number of CPUs (bsc#1051510).

  - ixgbe: do not set RXDCTL.RLPML for 82599 (bsc#1056657 ).

  - ixgbe: prevent ptp_rx_hang from running when in
    FILTER_ALL mode (bsc#1056657 bsc#1056653 ).

  - jbd2: if the journal is aborted then do not allow update
    of the log tail (bsc#1052766).

  - jffs2_kill_sb(): deal with failed allocations
    (bsc#1052766).

  - kabi protect struct acpi_nfit_desc (bsc#1091424).

  - kabi: add struct bpf_map back (References: bsc#1098425).

  - kabi: arm64: reserve space in cpu_hwcaps and
    cpu_hwcap_keys arrays (bsc#1089086).

  - kabi: arm64: update crc for cpu_hwcaps and
    cpu_hwcap_keys References: bsc#1089086

  - kcm: lock lower socket in kcm_attach
    (networking-stable-18_03_28).

  - kconfig: Avoid format overflow warning from GCC 8.1
    (bsc#1051510).

  - kconfig: Do not leak main menus during parsing
    (bsc#1051510).

  - kconfig: Fix automatic menu creation mem leak
    (bsc#1051510).

  - kconfig: Fix expr_free() E_NOT leak (bsc#1051510).

  - kernel/acct.c: fix the acct->needcheck check in
    check_free_space() (Git-fixes).

  - kernel/async.c: revert 'async: simplify
    lowest_in_progress()' (Git-fixes).

  - kernel/relay.c: limit kmalloc size to KMALLOC_MAX_SIZE
    (bsc#1051510).

  - kernel/relay.c: revert 'kernel/relay.c: fix potential
    memory leak' (Git-fixes).

  - kernel/signal.c: protect the SIGNAL_UNKILLABLE tasks
    from !sig_kernel_only() signals (Git-fixes).

  - kernel/signal.c: protect the traced SIGNAL_UNKILLABLE
    tasks from SIGKILL (Git-fixes).

  - kernel/signal.c: remove the no longer needed
    SIGNAL_UNKILLABLE check in complete_signal()
    (Git-fixes).

  - kexec: export PG_swapbacked to VMCOREINFO (bsc#1088354).

  - kexec_file: do not add extra alignment to efi memmap
    (bsc#1089268).

  - klp_symbols: make --klp-symbols argument semantic sane
    It selects build of klp symbols and defaults to off

  - kmod: fix wait on recursive loop (bsc#1099792).

  - kmod: reduce atomic operations on kmod_concurrent and
    simplify (bsc#1099792).

  - kmod: throttle kmod thread limit (bsc#1099792).

  - kobject: do not use WARN for registration failures
    (bsc#1051510).

  - kvm/x86: fix icebp instruction handling (bsc#1087088).

  - kvm: Introduce nopvspin kernel parameter (bsc#1056427).

  - kvm: nVMX: Enforce cpl=0 for VMX instructions
    (bsc#1099183).

  - l2tp: check sockaddr length in pppol2tp_connect()
    (networking-stable-18_04_26).

  - l2tp: do not accept arbitrary sockets (bsc#1076830).

  - lan78xx: Crash in lan78xx_writ_reg (Workqueue: events
    lan78xx_deferred_multicast_write)
    (networking-stable-18_04_10).

  - leds: pm8058: Silence pointer to integer size warning
    (bsc#1051510).

  - lib/kobject: Join string literals back (bsc#1051510).

  - lib/string_helpers: Add missed declaration of struct
    task_struct (bsc#1099918).

  - lib/test_bitmap.c: fix bitmap optimisation tests to
    report errors correctly (bsc#1051510).

  - libata: Apply NOLPM quirk for SanDisk SD7UB3Q*G1001 SSDs
    (bsc#1051510).

  - libata: Blacklist some Sandisk SSDs for NCQ
    (bsc#1051510).

  - libata: Drop SanDisk SD7UB3Q*G1001 NOLPM quirk
    (bsc#1051510).

  - libata: blacklist Micron 500IT SSD with MU01 firmware
    (bsc#1051510).

  - libata: zpodd: make arrays cdb static, reduces object
    code size (bsc#1051510).

  - libata: zpodd: small read overflow in eject_tray()
    (bsc#1051510).

  - libceph, ceph: change permission for readonly debugfs
    entries (bsc#1089115).

  - libceph: adding missing message types to
    ceph_msg_type_name() (bsc#1089115).

  - libceph: fix misjudgement of maximum monitor number
    (bsc#1089115).

  - libceph: reschedule a tick in finish_hunting()
    (bsc#1089115).

  - libceph: un-backoff on tick when we have a authenticated
    session (bsc#1089115).

  - libceph: validate con->state at the top of try_write()
    (bsc#1089115).

  - libnvdimm, btt: add a couple of missing kernel-doc lines
    (bsc#1087210).

  - libnvdimm, btt: clean up warning and error messages
    (bsc#1087205).

  - libnvdimm, btt: fix format string warnings
    (bsc#1087205).

  - libnvdimm, dimm: handle EACCES failures from label reads
    ().

  - libnvdimm, label: change min label storage size per UEFI
    2.7 (bsc#1091666).

  - libnvdimm, namespace: use a safe lookup for dimm device
    name (bsc#1095321).

  - libnvdimm, nfit: fix persistence domain reporting
    (bsc#1091424).

  - libnvdimm, pmem: Add sysfs notifications to badblocks
    ().

  - libnvdimm, pmem: Do not flush power-fail protected CPU
    caches (bsc#1091424).

  - libnvdimm, pmem: Unconditionally deep flush on *sync
    (bsc#1091424).

  - libnvdimm, region, pmem: fix 'badblocks'
    sysfs_get_dirent() reference lifetime ().

  - libnvdimm, region: hide persistence_domain when unknown
    (bsc#1091424).

  - libnvdimm: expose platform persistence attribute for
    nd_region (bsc#1091424).

  - libnvdimm: re-enable deep flush for pmem devices via
    fsync() (bsc#1091424).

  - livepatch: Allow to call a custom callback when freeing
    shadow variables (bsc#1071995 ).

  - livepatch: Initialize shadow variables safely by a
    custom callback (bsc#1071995 ).

  - llc: better deal with too small mtu
    (networking-stable-18_05_15).

  - llc: fix NULL pointer deref for SOCK_ZAPPED
    (networking-stable-18_04_26).

  - llc: hold llc_sap before release_sock()
    (networking-stable-18_04_26).

  - lock_parent() needs to recheck if dentry got
    __dentry_kill'ed under it (bsc#1052766).

  - locking/atomics, dm-integrity: Convert ACCESS_ONCE() to
    READ_ONCE()/WRITE_ONCE() (bsc#1093023).

  - locking/atomics: COCCINELLE/treewide: Convert trivial
    ACCESS_ONCE() patterns to READ_ONCE()/WRITE_ONCE()
    (bsc#1093023).

  - locking/qspinlock: Ensure node is initialised before
    updating prev->next (bsc#1050549).

  - locking/qspinlock: Ensure node->count is updated before
    initialising node (bsc#1050549).

  - locking: Remove smp_read_barrier_depends() from
    queued_spin_lock_slowpath() (bsc#1050549).

  - loop: handle short DIO reads (bsc#1052766).

  - lpfc: Fix 16gb hbas failing cq create (bsc#1093290).

  - lpfc: Fix port initialization failure (bsc#1093290).

  - lsm: fix smack_inode_removexattr and xattr_getsecurity
    memleak (bsc#1051510).

  - mac80211: Adjust SAE authentication timeout
    (bsc#1051510).

  - mac80211: Do not disconnect on invalid operating class
    (bsc#1051510).

  - mac80211: Fix condition validating WMM IE (bsc#1051510).

  - mac80211: Fix sending ADDBA response for an ongoing
    session (bsc#1051510).

  - mac80211: Fix setting TX power on monitor interfaces
    (bsc#1051510).

  - mac80211: drop frames with unexpected DS bits from
    fast-rx to slow path (bsc#1051510).

  - mac80211: mesh: fix wrong mesh TTL offset calculation
    (bsc#1051510).

  - mac80211: round IEEE80211_TX_STATUS_HEADROOM up to
    multiple of 4 (bsc#1051510).

  - mac80211: use timeout from the AddBA response instead of
    the request (bsc#1051510).

  - macros.kernel-source: define linux_arch for KMPs
    (boo#1098050). CONFIG_64BIT is no longer defined so KMP
    spec files need to include %{?linux_make_arch} in any
    make call to build modules or descent into the kernel
    directory for any reason.

  - macvlan: filter out unsupported feature flags
    (networking-stable-18_03_28).

  - macvlan: fix memory hole in macvlan_dev (bsc#1099918).

  - macvlan: remove unused fields in struct macvlan_dev
    (bsc#1099918).

  - mailbox: bcm-flexrm-mailbox: Fix FlexRM ring flush
    sequence (bsc#1051510).

  - mailbox: bcm-flexrm-mailbox: Fix mask used in
    CMPL_START_ADDR_VALUE() (bsc#1051510).

  - mailbox: mailbox-test: do not rely on rx_buffer content
    to signal data ready (bsc#1051510).

  - mbcache: initialize entry->e_referenced in
    mb_cache_entry_create() (bsc#1052766).

  - md raid10: fix NULL deference in
    handle_write_completed() (git-fixes).

  - md-cluster: choose correct label when clustered layout
    is not supported (bsc#1093023).

  - md-cluster: do not update recovery_offset for faulty
    device (bsc#1093023).

  - md-cluster: make function cluster_check_sync_size static
    (bsc#1093023).

  - md-multipath: Use seq_putc() in multipath_status()
    (bsc#1093023).

  - md/bitmap: clear BITMAP_WRITE_ERROR bit before writing
    it to sb (bsc#1093023).

  - md/bitmap: copy correct data for bitmap super
    (bsc#1093023).

  - md/bitmap: revert a patch (bsc#1093023).

  - md/r5cache: call mddev_lock/unlock() in
    r5c_journal_mode_show (bsc#1093023).

  - md/r5cache: fix io_unit handling in r5l_log_endio()
    (bsc#1093023).

  - md/r5cache: move mddev_lock() out of
    r5c_journal_mode_set() (bsc#1093023).

  - md/r5cache: print more info of log recovery
    (bsc#1093023).

  - md/raid0: attach correct cgroup info in bio
    (bsc#1093023).

  - md/raid1,raid10: silence warning about wait-within-wait
    (bsc#1093023).

  - md/raid1/10: add missed blk plug (bsc#1093023).

  - md/raid1: Fix trailing semicolon (bsc#1093023).

  - md/raid1: exit sync request if MD_RECOVERY_INTR is set
    (bsc#1093023).

  - md/raid1: fix NULL pointer dereference (bsc#1093023).

  - md/raid5: cap worker count (bsc#1093023).

  - md/raid5: correct degraded calculation in raid5_error
    (bsc#1093023).

  - md/raid5: simplify uninitialization of shrinker
    (bsc#1093023).

  - md: Delete gendisk before cleaning up the request queue
    (bsc#1093023).

  - md: allow metadata update while suspending
    (bsc#1093023).

  - md: always hold reconfig_mutex when calling
    mddev_suspend() (bsc#1093023).

  - md: be cautious about using ->curr_resync_completed for
    ->recovery_offset (bsc#1093023).

  - md: do not call bitmap_create() while array is quiesced
    (bsc#1093023).

  - md: do not check MD_SB_CHANGE_CLEAN in md_allow_write
    (bsc#1093023).

  - md: document lifetime of internal rdev pointer
    (bsc#1093023).

  - md: fix a potential deadlock of raid5/raid10 reshape
    (bsc#1093023).

  - md: fix a race condition for flush request handling
    (bsc#1093023).

  - md: fix deadlock error in recent patch (bsc#1093023).

  - md: fix md_write_start() deadlock w/o metadata devices
    (git-fixes).

  - md: fix two problems with setting the 're-add' device
    state (bsc#1098176).

  - md: forbid a RAID5 from having both a bitmap and a
    journal (bsc#1093023).

  - md: free unused memory after bitmap resize
    (bsc#1093023).

  - md: limit mdstat resync progress to max_sectors
    (bsc#1093023).

  - md: move suspend_hi/lo handling into core md code
    (bsc#1093023).

  - md: only allow remove_and_add_spares when no sync_thread
    running (bsc#1093023).

  - md: raid10: remove VLAIS (bsc#1093023).

  - md: raid10: remove a couple of redundant variables and
    initializations (bsc#1093023).

  - md: raid5: avoid string overflow warning (bsc#1093023).

  - md: release allocated bitset sync_set (bsc#1093023).

  - md: remove redundant variable q (bsc#1093023).

  - md: remove special meaning of ->quiesce(.., 2)
    (bsc#1093023).

  - md: rename some drivers/md/ files to have an 'md-'
    prefix (bsc#1093023).

  - md: replace seq_release_private with seq_release
    (bsc#1093023).

  - md: separate request handling (bsc#1093023).

  - md: use TASK_IDLE instead of blocking signals
    (bsc#1093023).

  - md: use lockdep_assert_held (bsc#1093023).

  - md: use mddev_suspend/resume instead of ->quiesce()
    (bsc#1093023).

  - media: atomisp_fops.c: disable atomisp_compat_ioctl32
    (bsc#1051510).

  - media: au0828: add VIDEO_V4L2 dependency (bsc#1051510).

  - media: cx231xx: Add support for AverMedia DVD EZMaker 7
    (bsc#1051510).

  - media: cx23885: Override 888 ImpactVCBe crystal
    frequency (bsc#1051510).

  - media: cx23885: Set subdev host data to clk_freq pointer
    (bsc#1051510).

  - media: dmxdev: fix error code for invalid ioctls
    (bsc#1051510).

  - media: dvb_frontend: fix locking issues at
    dvb_frontend_get_event() (bsc#1051510).

  - media: em28xx: Add Hauppauge SoloHD/DualHD bulk models
    (bsc#1051510).

  - media: em28xx: USB bulk packet size fix (bsc#1051510).

  - media: lgdt3306a: Fix a double kfree on i2c device
    remove (bsc#1051510).

  - media: lgdt3306a: Fix module count mismatch on usb
    unplug (bsc#1051510).

  - media: smiapp: fix timeout checking in smiapp_read_nvm
    (bsc#1099918).

  - media: uvcvideo: Support realtek's UVC 1.5 device
    (bsc#1099109).

  - media: v4l2-compat-ioctl32: do not oops on overlay
    (bsc#1051510).

  - media: v4l2-compat-ioctl32: prevent go past max size
    (bsc#1051510).

  - media: videobuf2-core: do not go out of the buffer range
    (bsc#1051510).

  - media: vivid: check if the cec_adapter is valid
    (bsc#1051510).

  - mei: me: add cannon point device ids ().

  - mei: me: add cannon point device ids for 4th device ().

  - mei: remove dev_err message on an unsupported ioctl
    (bsc#1051510).

  - mfd: cros ec: spi: Do not send first message too soon
    (bsc#1051510).

  - mfd: intel-lpss: Fix Intel Cannon Lake LPSS I2C input
    clock (bsc#1051510).

  - mfd: intel-lpss: Program REMAP register in PIO mode
    (bsc#1051510).

  - mkspec: only build docs for default variant kernel.

  - mlxsw: spectrum: Disable MAC learning for ovs port
    (networking-stable-17_12_31).

  - mlxsw: spectrum: Forbid linking to devices that have
    uppers FIX (stable-fixes).

  - mlxsw: spectrum: Prevent mirred-related crash on removal
    (networking-stable-17_10_09).

  - mlxsw: spectrum: Relax sanity checks during enslavement
    (networking-stable-18_01_12).

  - mlxsw: spectrum_buffers: Set a minimum quota for CPU
    port traffic (networking-stable-18_03_28).

  - mlxsw: spectrum_router: Do not log an error on missing
    neighbor (networking-stable-18_01_28).

  - mlxsw: spectrum_router: Fix NULL pointer deref
    (networking-stable-18_01_12).

  - mlxsw: spectrum_router: Fix error path in
    mlxsw_sp_vr_create (networking-stable-18_03_07).

  - mlxsw: spectrum_router: Simplify a piece of code
    (networking-stable-18_01_12).

  - mlxsw: spectrum_switchdev: Check success of FDB add
    operation (networking-stable-18_03_07).

  - mm, oom_reaper: skip mm structs with mmu notifiers
    (bsc#1099918).

  - mm, page_alloc: do not break __GFP_THISNODE by zonelist
    reset (bsc#1079152, VM Functionality).

  - mm, percpu: add support for __GFP_NOWARN flag
    (bsc#1089753).

  - mm, slab: reschedule cache_reap() on the same CPU (VM
    Functionality, bsc#1097796).

  - mm, swap: fix false error message in __swp_swapcount()
    (VM Functionality, bsc#1098043).

  - mm, swap: fix race between swap count continuation
    operations (VM Functionality, bsc#1097373). mm, swap:
    fix race between swap count continuation operations -
    KABI fix (VM Functionality, bsc#1097373).

  - mm, thp: do not cause memcg oom for thp (bnc#1089663).

  - mm/fadvise: discard partial page if endbyte is also EOF
    (bsc#1052766).

  - mm/filemap.c: fix NULL pointer in
    page_cache_tree_insert() (bsc#1052766).

  - mm/huge_memory.c: __split_huge_page() use atomic
    ClearPageDirty() (VM Functionality, bsc#1097800).

  - mm/khugepaged.c: convert VM_BUG_ON() to collapse fail
    (VM Functionality, bsc#1097468).

  - mm/ksm.c: fix inconsistent accounting of zero pages (VM
    Functionality, bsc#1097780).

  - mm/mempolicy.c: avoid use uninitialized preferred_node
    (VM Functionality, bsc#1097465).

  - mm/page_owner: fix recursion bug after changing skip
    entries (VM Functionality, bsc#1097472).

  - mm/pkeys, powerpc, x86: Provide an empty vma_pkey() in
    linux/pkeys.h (bsc#1078248).

  - mm/pkeys, x86, powerpc: Display pkey in smaps if arch
    supports pkeys (bsc#1078248).

  - mm/pkeys: Add an empty arch_pkeys_enabled()
    (bsc#1078248).

  - mm/pkeys: Remove include of asm/mmu_context.h from
    pkeys.h (bsc#1078248).

  - mm/shmem: do not wait for lock_page() in
    shmem_unused_huge_shrink() (bnc#1089667).

  - mm/thp: do not wait for lock_page() in
    deferred_split_scan() (VM Functionality, bsc#1097470).

  - mm: Fix memory size alignment in
    devm_memremap_pages_release() (VM Functionality,
    bsc#1097439).

  - mm: fix device-dax pud write-faults triggered by
    get_user_pages() (bsc#1052766).

  - mm: fix the NULL mapping case in __isolate_lru_page()
    (bnc#971975 VM -- git fixes).

  - mmc: dw_mmc: Fix the DTO/CTO timeout overflow
    calculation for 32-bit systems (bsc#1088713).

  - mmc: dw_mmc: exynos: fix the suspend/resume issue for
    exynos5433 (bsc#1051510).

  - mmc: jz4740: Fix race condition in IRQ mask update
    (bsc#1051510).

  - mmc: sdhci-iproc: add SDHCI_QUIRK2_HOST_OFF_CARD_ON for
    cygnus (bsc#1051510).

  - mmc: sdhci-iproc: fix 32bit writes for TRANSFER_MODE
    register (bsc#1051510).

  - mmc: sdhci-iproc: remove hard coded mmc cap 1.8v
    (bsc#1051510).

  - mmc: sdhci-pci: Fix voltage switch for some Intel host
    controllers (bsc#1051510).

  - mmc: sdhci-pci: Only do AMD tuning for HS200
    (bsc#1051510).

  - mq-deadline: Enable auto-loading when built as module
    (bsc#1099918).

  - mremap: Remove LATENCY_LIMIT from mremap to reduce the
    number of TLB shootdowns (bnc#1095115).

  - mtd: cmdlinepart: Update comment for introduction of
    OFFSET_CONTINUOUS (bsc#1099918).

  - mtd: jedec_probe: Fix crash in jedec_read_mfr()
    (bsc#1099918).

  - mtd: nand: fsl_ifc: Fix eccstat array overflow for IFC
    ver >= 2.0.0 (bsc#1099918).

  - mtd: partitions: add helper for deleting partition
    (bsc#1099918).

  - mtd: partitions: remove sysfs files when deleting all
    master's partitions (bsc#1099918).

  - mtd: ubi: wl: Fix error return code in ubi_wl_init()
    (bsc#1051510).

  - mwifiex: pcie: tighten a check in
    mwifiex_pcie_process_event_ready() (bsc#1051510).

  - n_tty: Access echo_* variables carefully (bsc#1051510).

  - n_tty: Fix stall at n_tty_receive_char_special()
    (bsc#1051510).

  - n_tty: fix EXTPROC vs ICANON interaction with TIOCINQ
    (aka FIONREAD) (bnc#1094825).

  - nbd: do not start req until after the dead connection
    logic (bsc#1099918).

  - nbd: fix -ERESTARTSYS handling (bsc#1099918).

  - nbd: fix nbd device deletion (bsc#1099918).

  - nbd: fix return value in error handling path
    (bsc#1099918).

  - nbd: wait uninterruptible for the dead timeout
    (bsc#1099918).

  - net sched actions: fix refcnt leak in skbmod
    (networking-stable-18_05_15).

  - net sched actions: return explicit error when tunnel_key
    mode is not specified (bsc#1056787).

  - net/ipv6: Fix route leaking between VRFs
    (networking-stable-18_04_10).

  - net/ipv6: Increment OUTxxx counters after netfilter hook
    (networking-stable-18_04_10).

  - net/iucv: Free memory obtained by kzalloc
    (networking-stable-18_03_28).

  - net/mlx4_en: Fix an error handling path in
    'mlx4_en_init_netdev()' (networking-stable-18_05_15).

  - net/mlx4_en: Verify coalescing parameters are in range
    (networking-stable-18_05_15).

  - net/mlx5: Avoid cleaning flow steering table twice
    during error flow (bsc#1091532).

  - net/mlx5: E-Switch, Include VF RDMA stats in vport
    statistics (networking-stable-18_05_15).

  - net/mlx5: Eliminate query xsrq dead code (bsc#1046303 ).

  - net/mlx5: Fix build break when CONFIG_SMP=n (bsc#1046303
    ).

  - net/mlx5: Fix mlx5_get_vector_affinity function
    (bsc#1046303 ).

  - net/mlx5e: Allow offloading ipv4 header re-write for
    icmp (bsc#1046303 ).

  - net/mlx5e: Do not reset Receive Queue params on every
    type change (bsc#1046303 ).

  - net/mlx5e: Err if asked to offload TC match on frag
    being first (networking-stable-18_05_15).

  - net/mlx5e: Fixed sleeping inside atomic context
    (bsc#1046303 ).

  - net/mlx5e: Remove unused define
    MLX5_MPWRQ_STRIDES_PER_PAGE (bsc#1046303 ).

  - net/mlx5e: TX, Use correct counter in dma_map error flow
    (networking-stable-18_05_15).

  - net/sched: cls_u32: fix cls_u32 on filter replace
    (networking-stable-18_03_07).

  - net/sched: fix NULL dereference in the error path of
    tcf_bpf_init() (bsc#1056787).

  - net/sched: fix NULL dereference in the error path of
    tunnel_key_init() (bsc#1056787).

  - net/sched: fix NULL dereference on the error path of
    tcf_skbmod_init() (bsc#1056787).

  - net/sctp: Always set scope_id in sctp_inet6_skb_msgname
    (networking-stable-17_11_20).

  - net/unix: do not show information about sockets from
    other namespaces (networking-stable-17_11_14).

  - net/usb/qmi_wwan.c: Add USB id for lt4120 modem
    (bsc#1087092).

  - net: Allow neigh contructor functions ability to modify
    the primary_key (networking-stable-18_01_28).

  - net: Fix hlist corruptions in inet_evict_bucket()
    (networking-stable-18_03_28).

  - net: Only honor ifindex in IP_PKTINFO if non-0
    (networking-stable-18_03_28).

  - net: Set sk_prot_creator when cloning sockets to the
    right proto (networking-stable-17_10_09).

  - net: af_packet: fix race in PACKET_{R|T}X_RING
    (networking-stable-18_04_26).

  - net: bonding: Fix transmit load balancing in balance-alb
    mode if specified by sysfs (networking-stable-17_10_09).

  - net: bonding: fix tlb_dynamic_lb default value
    (networking-stable-17_10_09).

  - net: bridge: fix early call to br_stp_change_bridge_id
    and plug newlink leaks (networking-stable-17_12_31).

  - net: bridge: fix returning of vlan range op errors
    (networking-stable-17_11_14).

  - net: core: fix module type in sock_diag_bind
    (networking-stable-18_01_12).

  - net: dsa: bcm_sf2: Clear IDDQ_GLOBAL_PWR bit for PHY
    (networking-stable-17_12_31).

  - net: dsa: check master device before put
    (networking-stable-17_11_14).

  - net: dsa: mv88e6xxx: lock mutex when freeing IRQs
    (networking-stable-17_10_09).

  - net: emac: Fix napi poll list corruption
    (networking-stable-17_10_09).

  - net: ethernet: arc: Fix a potential memory leak if an
    optional regulator is deferred
    (networking-stable-18_03_28).

  - net: ethernet: sun: niu set correct packet size in skb
    (networking-stable-18_05_15).

  - net: ethernet: ti: cpsw: add check for in-band mode
    setting with RGMII PHY interface
    (networking-stable-18_03_28).

  - net: ethernet: ti: cpsw: fix net watchdog timeout
    (networking-stable-18_03_07).

  - net: ethernet: ti: cpsw: fix packet leaking in dual_mac
    mode (networking-stable-18_05_15).

  - net: ethernet: ti: cpsw: fix tx vlan priority mapping
    (networking-stable-18_04_26).

  - net: ethtool: Add missing kernel doc for FEC parameters
    (bsc#1046540 ).

  - net: fec: Fix unbalanced PM runtime calls
    (networking-stable-18_03_28).

  - net: fec: defer probe if regulator is not ready
    (networking-stable-18_01_12).

  - net: fec: free/restore resource in related probe error
    pathes (networking-stable-18_01_12).

  - net: fec: restore dev_id in the cases of probe error
    (networking-stable-18_01_12).

  - net: fec: unmap the xmit buffer that are not transferred
    by DMA (networking-stable-17_12_31).

  - net: fix deadlock while clearing neighbor proxy table
    (networking-stable-18_04_26).

  - net: fix possible out-of-bound read in
    skb_network_protocol() (networking-stable-18_04_10).

  - net: fool proof dev_valid_name()
    (networking-stable-18_04_10).

  - net: igmp: Use correct source address on IGMPv3 reports
    (networking-stable-17_12_31).

  - net: igmp: add a missing rcu locking section
    (git-fixes).

  - net: igmp: fix source address check for IGMPv3 reports
    (git-fixes).

  - net: ipv4: avoid unused variable warning for sysctl
    (git-fixes).

  - net: ipv4: do not allow setting net.ipv4.route.min_pmtu
    below 68 (networking-stable-18_03_07).

  - net: ipv6: keep sk status consistent after datagram
    connect failure (networking-stable-18_03_28).

  - net: mvmdio: disable/unprepare clocks in EPROBE_DEFER
    case (networking-stable-17_12_31).

  - net: phy: Fix mask value write on gmii2rgmii converter
    speed register (networking-stable-17_10_09).

  - net: phy: Tell caller result of phy_change()
    (networking-stable-18_03_28).

  - net: phy: fix phy_start to consider PHY_IGNORE_INTERRUPT
    (networking-stable-18_03_07).

  - net: phy: marvell: Limit 88m1101 autoneg errata to
    88E1145 as well (networking-stable-17_12_31).

  - net: phy: micrel: ksz9031: reconfigure autoneg after phy
    autoneg workaround (networking-stable-17_12_31).

  - net: qcom/emac: specify the correct size when mapping a
    DMA buffer (networking-stable-17_10_09).

  - net: qdisc_pkt_len_init() should be more robust
    (networking-stable-18_01_28).

  - net: qlge: use memmove instead of
    skb_copy_to_linear_data (bsc#1050529 bsc#1086319 ).

  - net: realtek: r8169: implement set_link_ksettings()
    (networking-stable-17_12_12).

  - net: reevalulate autoflowlabel setting after sysctl
    setting (networking-stable-17_12_31).

  - net: remove hlist_nulls_add_tail_rcu()
    (networking-stable-17_12_12).

  - net: sched: fix error path in tcf_proto_create() when
    modules are not configured (networking-stable-18_05_15).

  - net: sched: ife: check on metadata length
    (networking-stable-18_04_26).

  - net: sched: ife: handle malformed tlv length
    (networking-stable-18_04_26).

  - net: sched: ife: signal not finding metaid
    (networking-stable-18_04_26).

  - net: sched: report if filter is too large to dump
    (networking-stable-18_03_07).

  - net: stmmac: enable EEE in MII, GMII or RGMII only
    (networking-stable-18_01_12).

  - net: support compat 64-bit time in {s,g}etsockopt
    (networking-stable-18_05_15).

  - net: systemport: Correct IPG length settings
    (networking-stable-17_11_20).

  - net: systemport: Rewrite __bcm_sysport_tx_reclaim()
    (networking-stable-18_03_28).

  - net: tcp: close sock if net namespace is exiting
    (networking-stable-18_01_28).

  - net: validate attribute sizes in neigh_dump_table()
    (networking-stable-18_04_26).

  - net: vrf: Add support for sends to local broadcast
    address (networking-stable-18_01_28).

  - net_sched: fq: take care of throttled flows before reuse
    (networking-stable-18_05_15).

  - netfilter/ipvs: clear ipvs_property flag when SKB net
    namespace changed (networking-stable-17_11_20).

  - netfilter: use skb_to_full_sk in ip6_route_me_harder
    (bsc#1076830).

  - netlink: avoid a double skb free in genlmsg_mcast()
    (git-fixes).

  - netlink: do not proceed if dump's start() errs
    (networking-stable-17_10_09).

  - netlink: do not set cb_running if dump's start() errs
    (networking-stable-17_11_14).

  - netlink: ensure to loop over all netns in
    genlmsg_multicast_allns() (networking-stable-18_03_07).

  - netlink: extack needs to be reset each time through loop
    (networking-stable-18_01_28).

  - netlink: make sure nladdr has correct size in
    netlink_connect() (networking-stable-18_04_10).

  - netlink: put module reference if dump start fails
    (git-fixes).

  - netlink: reset extack earlier in netlink_rcv_skb
    (networking-stable-18_01_28).

  - nfit-test: Add platform cap support from ACPI 6.2a to
    test (bsc#1091424).

  - nfit: skip region registration for incomplete control
    regions (bsc#1091666).

  - nfp: use full 40 bits of the NSP buffer address
    (bsc#1055968).

  - nfs: system crashes after NFS4ERR_MOVED recovery
    (git-fixes).

  - nfsd: fix incorrect umasks (git-fixes).

  - nl80211: relax ht operation checks for mesh
    (bsc#1051510).

  - nubus: Avoid array underflow and overflow (bsc#1099918).

  - nubus: Fix up header split (bsc#1099918).

  - nvme-fabrics: allow duplicate connections to the
    discovery controller (bsc#1098706).

  - nvme-fabrics: allow internal passthrough command on
    deleting controllers (bsc#1098706).

  - nvme-fabrics: centralize discovery controller defaults
    (bsc#1098706).

  - nvme-fabrics: fix and refine state checks in
    __nvmf_check_ready (bsc#1098706).

  - nvme-fabrics: handle the admin-only case properly in
    nvmf_check_ready (bsc#1098706).

  - nvme-fabrics: refactor queue ready check (bsc#1098706).

  - nvme-fabrics: remove unnecessary controller subnqn
    validation (bsc#1098706).

  - nvme-fc: change controllers first connect to use
    reconnect path (bsc#1098706).

  - nvme-fc: fix nulling of queue data on reconnect
    (bsc#1098706).

  - nvme-fc: release io queues to allow fast fail
    (bsc#1098706).

  - nvme-fc: remove reinit_request routine (bsc#1098706).

  - nvme-fc: remove setting DNR on exception conditions
    (bsc#1098706).

  - nvme-multipath: fix sysfs dangerously created links
    (bsc#1096529).

  - nvme-rdma: Do not flush delete_wq by default during
    remove_one (bsc#1089977).

  - nvme-rdma: Fix command completion race at error recovery
    (bsc#1099041).

  - nvme-rdma: correctly check for target keyed sgl support
    (bsc#1099041).

  - nvme-rdma: do not override opts->queue_size
    (bsc#1099041).

  - nvme-rdma: fix error flow during mapping request data
    (bsc#1099041).

  - nvme-rdma: fix possible double free condition when
    failing to create a controller (bsc#1099041).

  - nvme/multipath: Fix multipath disabled naming collisions
    (bsc#1098706).

  - nvme: Set integrity flag for user passthrough commands
    (bsc#1098706).

  - nvme: Skip checking heads without namespaces
    (bsc#1098706).

  - nvme: Use admin command effects for admin commands
    (bsc#1098706).

  - nvme: add quirk to force medium priority for SQ creation
    ().

  - nvme: allow duplicate controller if prior controller
    being deleted (bsc#1098706).

  - nvme: check return value of init_srcu_struct function
    (bsc#1098706).

  - nvme: do not send keep-alives to the discovery
    controller ().

  - nvme: expand nvmf_check_if_ready checks (bsc#1098706).

  - nvme: fix NULL pointer dereference in
    nvme_init_subsystem (bsc#1098706).

  - nvme: fix extended data LBA supported setting ().

  - nvme: fix lockdep warning in
    nvme_mpath_clear_current_path ().

  - nvme: fix potential memory leak in option parsing
    (bsc#1098706).

  - nvme: move init of keep_alive work item to controller
    initialization (bsc#1098706).

  - nvme: target: fix buffer overflow ().

  - nvmet-fc: increase LS buffer count per fc port
    (bsc#1098706).

  - nvmet-rdma: Do not flush system_wq by default during
    remove_one (bsc#1089977).

  - nvmet: fix space padding in serial number ().

  - nvmet: switch loopback target state to connecting when
    resetting (bsc#1098706).

  - objtool, perf: Fix GCC 8 -Wrestrict error (Fix gcc 8
    restrict error).

  - ocfs2/acl: use 'ip_xattr_sem' to protect getting
    extended attribute (bsc#1052766).

  - ocfs2/dlm: Fix up kABI in dlm_ctxt (bsc#1052766).

  - ocfs2/dlm: wait for dlm recovery done when migrating all
    lock resources (bsc#1052766).

  - ocfs2: return -EROFS to mount.ocfs2 if inode block is
    invalid (bsc#1052766).

  - of: overlay: validate offset from property fixups
    (bsc#1051510).

  - of: platform: stop accessing invalid dev in
    of_platform_device_destroy (bsc#1051510).

  - of: unittest: for strings, account for trailing \0 in
    property length field (bsc#1051510).

  - omapdrm: panel: fix compatible vendor string for
    td028ttec1 (bsc#1051510).

  - openvswitch: Do not swap table in nlattr_set() after
    OVS_ATTR_NESTED is found (networking-stable-18_05_15).

  - ovl: Put upperdentry if ovl_check_origin() fails
    (bsc#1088704).

  - ovl: Return -ENOMEM if an allocation fails ovl_lookup()
    (bsc#1096065).

  - ovl: fix failure to fsync lower dir.

  - ovl: fix lookup with middle layer opaque dir and
    absolute path redirects (bsc#1090605).

  - ovl: treat btrfs mounts as different superblocks
    (bsc#1059336).

  - p54: do not unregister leds when they are not
    initialized (bsc#1051510).

  - parport_pc: Add support for WCH CH382L PCI-E single
    parallel port card (bsc#1051510).

  - partitions/msdos: Unable to mount UFS 44bsd partitions
    (bsc#1051510).

  - pinctrl/amd: Fix build dependency on pinmux code
    (bsc#1051510).

  - pinctrl/amd: save pin registers over suspend/resume
    (bsc#1051510).

  - pinctrl: adi2: Fix Kconfig build problem (bsc#1051510).

  - pinctrl: armada-37xx: Fix direction_output() callback
    behavior (bsc#1051510).

  - pinctrl: artpec6: dt: add missing pin group uart5nocts
    (bsc#1051510).

  - pinctrl: baytrail: Enable glitch filter for GPIOs used
    as interrupts (bsc#1051510).

  - pinctrl: denverton: Fix UART2 RTS pin mode
    (bsc#1051510).

  - pinctrl: pxa: pxa2xx: add missing
    MODULE_DESCRIPTION/AUTHOR/LICENSE (bsc#1051510).

  - pinctrl: rockchip: enable clock when reading pin
    direction register (bsc#1051510).

  - pinctrl: samsung: Fix NULL pointer exception on external
    interrupts on S3C24xx (bsc#1051510).

  - pinctrl: samsung: Fix invalid register offset used for
    Exynos5433 external interrupts (bsc#1051510).

  - pinctrl: sh-pfc: r8a7795-es1: Fix MOD_SEL1 bit[25:24] to
    0x3 when using STP_ISEN_1_D (bsc#1051510).

  - pinctrl: sh-pfc: r8a7796: Fix MOD_SEL register pin
    assignment for SSI pins group (bsc#1051510).

  - pinctrl: sunxi: Fix A64 UART mux value (bsc#1051510).

  - pinctrl: sunxi: Fix A80 interrupt pin bank
    (bsc#1051510).

  - pinctrl: sx150x: Add a static gpio/pinctrl pin range
    mapping (bsc#1051510).

  - pinctrl: sx150x: Register pinctrl before adding the
    gpiochip (bsc#1051510).

  - pinctrl: sx150x: Unregister the pinctrl on release
    (bsc#1051510).

  - pipe: fix off-by-one error when checking buffer limits
    (bsc#1051510).

  - pktcdvd: Fix a recently introduced NULL pointer
    dereference (bsc#1099918).

  - pktcdvd: Fix pkt_setup_dev() error path (bsc#1099918).

  - platform/chrome: Use proper protocol transfer function
    (bsc#1051510).

  - platform/chrome: cros_ec_lpc: remove redundant pointer
    request (bsc#1051510).

  - platform/x86: asus-wireless: Fix NULL pointer
    dereference (bsc#1051510).

  - platform/x86: asus-wmi: Fix NULL pointer dereference
    (bsc#1051510).

  - platform/x86: fujitsu-laptop: Support Lifebook U7x7
    hotkeys (bsc#1087284).

  - platform/x86: ideapad-laptop: Add MIIX 720-12IKB to
    no_hw_rfkill (bsc#1093035).

  - platform/x86: ideapad-laptop: Apply no_hw_rfkill to
    Y20-15IKBM, too (bsc#1098626).

  - platform/x86: thinkpad_acpi: suppress warning about palm
    detection (bsc#1051510).

  - power: supply: ab8500_charger: Bail out in case of error
    in 'ab8500_charger_init_hw_registers()' (bsc#1051510).

  - power: supply: ab8500_charger: Fix an error handling
    path (bsc#1051510).

  - power: supply: axp288_charger: Properly stop work on
    probe-error / remove (bsc#1051510).

  - powerpc/64/kexec: fix race in kexec when XIVE is
    shutdown (bsc#1088273). Refresh patchset with upstream
    patches

  - powerpc/64s/idle: Fix restore of AMOR on POWER9 after
    deep sleep (bsc#1055186, ).

  - powerpc/64s/idle: avoid sync for KVM state when waking
    from idle (bsc#1061840).

  - powerpc/64s: Add all POWER9 features to CPU_FTRS_ALWAYS
    (bsc#1055117).

  - powerpc/64s: Enable barrier_nospec based on firmware
    settings (bsc#1068032, bsc#1080157). Delete
    patches.arch/powerpc-64-barrier_nospec-Add-commandline-t
    rigger.patch. Delete
    patches.arch/powerpc-64s-barrier_nospec-Add-hcall-trigge
    r.patch.

  - powerpc/64s: Enhance the information in
    cpu_show_spectre_v1() (bsc#1068032).

  - powerpc/64s: Explicitly add vector features to
    CPU_FTRS_POSSIBLE (bsc#1055117).

  - powerpc/64s: Fix CPU_FTRS_ALWAYS vs DT CPU features
    (bsc#1055117).

  - powerpc/64s: Fix POWER9 DD2.2 and above in DT CPU
    features (bsc#1055117).

  - powerpc/64s: Fix POWER9 DD2.2 and above in cputable
    features (bsc#1055117).

  - powerpc/64s: Fix dt_cpu_ftrs to have restore_cpu clear
    unwanted LPCR bits (bsc#1055117).

  - powerpc/64s: Fix mce accounting for powernv
    (bsc#1094244).

  - powerpc/64s: Fix pkey support in dt_cpu_ftrs, add
    CPU_FTR_PKEY bit (bsc#1055117).

  - powerpc/64s: Refine feature sets for little endian
    builds (bsc#1055117).

  - powerpc/64s: Remove POWER4 support (bsc#1055117).

  - powerpc/64s: Set assembler machine type to POWER4
    (bsc#1055117).

  - powerpc/fadump: Do not use hugepages when fadump is
    active (bsc#1092772).

  - powerpc/fadump: exclude memory holes while reserving
    memory in second kernel (bsc#1092772).

  - powerpc/kvm: Fix guest boot failure on Power9 since DAWR
    changes (bsc#1061840).

  - powerpc/kvm: Fix lockups when running KVM guests on
    Power8 (bsc#1061840).

  - powerpc/lib: Fix off-by-one in alternate feature
    patching (bsc#1065729).

  - powerpc/livepatch: Fix KABI breaker in stacktrace.c
    (bsc#1071995 bsc#1072856 bsc#1087458 bsc#1089664
    bsc#1089669).

  - powerpc/livepatch: Fix build error with kprobes disabled
    (bsc#1071995 ).

  - powerpc/mm/radix: Fix always false comparison against
    MMU_NO_CONTEXT (bsc#1055186, ).

  - powerpc/mm/radix: Fix checkstops caused by invalid
    tlbiel (bsc#1055186, ).

  - powerpc/mm/radix: Parse disable_radix commandline
    correctly (bsc#1055186, ).

  - powerpc/mm/radix: Update command line parsing for
    disable_radix (bsc#1055186, ).

  - powerpc/mm/radix: Update pte fragment count from 16 to
    256 on radix (bsc#1055186, ).

  - powerpc/mm: Add a CONFIG option to choose if radix is
    used by default (bsc#1055186, ).

  - powerpc/mm: Fix thread_pkey_regs_init() (bsc#1078248,
    git-fixes).

  - powerpc/perf: Add blacklisted events for Power9 DD2.1
    (bsc1056686).

  - powerpc/perf: Add blacklisted events for Power9 DD2.2
    (bsc1056686).

  - powerpc/perf: Fix kernel address leak via sampling
    registers (bsc1056686).

  - powerpc/perf: Infrastructure to support addition of
    blacklisted events (bsc1056686).

  - powerpc/perf: Prevent kernel address leak to userspace
    via BHRB buffer (bsc1056686).

  - powerpc/perf: Prevent kernel address leak via
    perf_get_data_addr() (bsc1056686).

  - powerpc/perf: fix bug references.

  - powerpc/pkeys: Detach execute_only key on !PROT_EXEC
    (bsc#1078248, git-fixes).

  - powerpc/pkeys: Drop private VM_PKEY definitions
    (bsc#1078248).

  - powerpc/pseries: Restore default security feature flags
    on setup (bsc#1068032). Refresh
    patches.arch/powerpc-64s-barrier_nospec-Add-hcall-trigge
    r.patch.

  - powerpc/ptrace: Fix enforcement of DAWR constraints
    (bsc#1099918).

  - powerpc/xive: Fix wrong xmon output caused by typo
    (bsc#1088273).

  - powerpc/xmon: Also setup debugger hooks when
    single-stepping (bsc#1072829).

  - powerpc64/ftrace: Add a field in paca to disable ftrace
    in unsafe code paths (bsc#1088804).

  - powerpc64/ftrace: Add helpers to hard disable ftrace
    (bsc#1088804).

  - powerpc64/ftrace: Delay enabling ftrace on secondary
    cpus (bsc#1088804).

  - powerpc64/ftrace: Disable ftrace during hotplug
    (bsc#1088804).

  - powerpc64/ftrace: Disable ftrace during kvm guest
    entry/exit (bsc#1088804).

  - powerpc64/ftrace: Rearrange #ifdef sections in ftrace.h
    (bsc#1088804).

  - powerpc64/ftrace: Use the generic version of
    ftrace_replace_code() (bsc#1088804).

  - powerpc64/kexec: Hard disable ftrace before switching to
    the new kernel (bsc#1088804).

  - powerpc64/module: Tighten detection of mcount call sites
    with -mprofile-kernel (bsc#1088804).

  - powerpc: Add ppc_breakpoint_available() (bsc#1055117).

  - powerpc: Machine check interrupt is a non-maskable
    interrupt (bsc#1094244).

  - powerpc: Remove unused CPU_FTR_ARCH_201 (bsc#1055117).

  - powerpc: Use barrier_nospec in copy_from_user()
    (bsc#1068032, bsc#1080157).

  - ppc64le: reliable stacktrace: handle graph traced
    functions (bsc#1089664).

  - ppc64le: reliable stacktrace: mark stacktraces with
    exception frames as unreliable (bsc#1089669).

  - ppc64le: reliable stacktrace: mark stacktraces with
    kretprobe_trampoline as unreliable (bsc#1090522).

  - ppp: avoid loop in xmit recursion detection code
    (networking-stable-18_03_28).

  - ppp: fix race in ppp device destruction
    (networking-stable-17_11_14).

  - ppp: prevent unregistered channels from connecting to
    PPP units (networking-stable-18_03_07).

  - ppp: unlock all_ppp_mutex before registering device
    (networking-stable-18_01_28).

  - pppoe: check sockaddr length in pppoe_connect()
    (networking-stable-18_04_26).

  - pppoe: take ->needed_headroom of lower device into
    account on xmit (networking-stable-18_01_28).

  - pptp: remove a buggy dst release in pptp_connect()
    (networking-stable-18_04_10).

  - printk: fix possible reuse of va_list variable
    (bsc#1100602).

  - procfs: add tunable for fd/fdinfo dentry retention
    (bsc#1086652).

  - ptr_ring: add barriers (networking-stable-17_12_31).

  - pty: cancel pty slave port buf's work in tty_release
    (bsc#1051510).

  - pwm: lpss: platform: Save/restore the ctrl register over
    a suspend/resume (bsc#1051510).

  - pwm: rcar: Fix a condition to prevent mismatch value
    setting to duty (bsc#1051510).

  - pwm: stmpe: Fix wrong register offset for hwpwm=2 case
    (bsc#1051510).

  - qed: Fix l2 initializations over iWARP personality
    (bsc#1050536 bsc#1050545 ).

  - qed: Fix non TCP packets should be dropped on iWARP ll2
    connection (bsc#1050545 ).

  - qed: Free RoCE ILT Memory on rmmod qedr (bsc#1050536
    bsc#1050545 ).

  - qed: Use after free in qed_rdma_free() (bsc#1050536
    bsc#1050545 ).

  - qede: Fix gfp flags sent to rdma event node allocation
    (bsc#1050538 bsc#1050545 ).

  - qede: Fix qedr link update (bsc#1050538 bsc#1050545 ).

  - qla2xxx: Enable T10-DIF with FC-NVMe enabled
    (bsc#1091264).

  - qla2xxx: Mask off Scope bits in retry delay
    (bsc#1068054).

  - qmi_wwan: Add missing skb_reset_mac_header-call
    (networking-stable-17_11_20).

  - qmi_wwan: Add support for Quectel EP06
    (networking-stable-18_02_06).

  - qmi_wwan: do not steal interfaces from class drivers
    (bsc#1092888).

  - r8169: fix powering up RTL8168h (bsc#1051510).

  - r8169: fix setting driver_data after register_netdev
    (bsc#1051510).

  - radeon: hide pointless #warning when compile testing
    (bsc#1051510).

  - radix tree test suite: add item_delete_rcu()
    (bsc#1095467).

  - radix tree test suite: fix compilation issue
    (bsc#1095467).

  - radix tree test suite: fix mapshift build target
    (bsc#1095467).

  - radix tree test suite: multi-order iteration race
    (bsc#1095467).

  - radix tree: fix multi-order iteration race
    (bsc#1095467).

  - raid10: check bio in r10buf_pool_free to void NULL
    pointer dereference (bsc#1098174).

  - raid1: copy write hint from master bio to behind bio
    (bsc#1093023).

  - raid1: prevent freeze_array/wait_all_barriers deadlock
    (bsc#1093023).

  - raid1: remove obsolete code in raid1_write_request
    (bsc#1093023).

  - raid5-ppl: PPL support for disks with write-back cache
    enabled (bsc#1093023).

  - raid5-ppl: fix handling flush requests (bsc#1093023).

  - raid5: Set R5_Expanded on parity devices as well as data
    (bsc#1093023).

  - raid5: remove raid5_build_block (bsc#1093023).

  - raid: remove tile specific raid6 implementation
    (bsc#1093023).

  - random: crng_reseed() should lock the crng instance that
    it is modifying (bsc#1051510).

  - random: use a different mixing algorithm for
    add_device_randomness() (bsc#1051510).

  - random: use a tighter cap in credit_entropy_bits_safe()
    (bsc#1051510).

  - rbd: use GFP_NOIO for parent stat and data requests
    (bsc#1093728).

  - rds: Incorrect reference counting in TCP socket creation
    (bsc#1076830).

  - rds: MP-RDS may use an invalid c_path
    (networking-stable-18_04_13).

  - rds: do not leak kernel memory to user land
    (networking-stable-18_05_15).

  - regulator: Do not return or expect -errno from
    of_map_mode() (bsc#1099029).

  - regulator: cpcap: Fix standby mode (bsc#1051510).

  - regulator: gpio: Fix some error handling paths in
    'gpio_regulator_probe()' (bsc#1091960).

  - regulator: of: Add a missing 'of_node_put()' in an error
    handling path of 'of_regulator_match()' (bsc#1051510).

  - reiserfs: mark read-write mode unsupported ().

  - reiserfs: package in separate KMP ().

  - resource: fix integer overflow at reallocation
    (bsc#1086739).

  - restore cond_resched() in shrink_dcache_parent()
    (bsc#1098599).

  - rfkill: gpio: fix memory leak in probe error path
    (bsc#1051510).

  - rhashtable: Fix rhlist duplicates insertion
    (bsc#1051510).

  - rmdir(),rename(): do shrink_dcache_parent() only on
    success (bsc#1100340).

  - rocker: fix possible NULL pointer dereference in
    rocker_router_fib_event_work
    (networking-stable-18_02_06).

  - route: check sysctl_fib_multipath_use_neigh earlier than
    hash (networking-stable-18_04_10).

  - rpm/config.sh: Fixup BUGZILLA_PRODUCT variable

  - rpm/kernel-docs.spec.in: Fix and cleanup for 4.13 doc
    build (bsc#1048129) The whole DocBook stuff has been
    deleted. The PDF build still non-working thus the
    sub-packaging disabled so far.

  - rpm/kernel-source.changes.old: Add pre-SLE15 history
    (bsc#1098995).

  - rpm/modules.fips include module list from dracut

  - rpm: fix typo, SUSE_KERNEL_RELEASE ->
    SUSE_KERNEL_RELEASED (bsc#1095104). This causes release
    kernels to report as (unreleased).

  - rt2x00: do not pause queue unconditionally on error path
    (bsc#1051510).

  - rtc-opal: Fix handling of firmware error codes, prevent
    busy loops (bsc#1051510).

  - rtc: hctosys: Ensure system time does not overflow
    time_t (bsc#1051510).

  - rtc: pcf8563: fix output clock rate (bsc#1051510).

  - rtc: pl031: make interrupt optional (bsc#1051510).

  - rtc: snvs: Fix usage of snvs_rtc_enable (bsc#1051510).

  - rtc: tx4939: avoid unintended sign extension on a 24 bit
    shift (bsc#1051510).

  - rtl8187: Fix NULL pointer dereference in
    priv->conf_mutex (bsc#1051510).

  - rtlwifi: rtl8192cu: Remove variable self-assignment in
    rf.c (bsc#1051510).

  - rxrpc: Fix send in rxrpc_send_data_packet()
    (networking-stable-18_03_07).

  - s390/archrandom: Reconsider s390 arch random
    implementation (bnc#1096753, LTC#168037).

  - s390/archrandom: Rework arch random implementation
    (bnc#1096753, LTC#168037).

  - s390/cio: update chpid descriptor after resource
    accessibility event (bnc#1093148, LTC#167307).

  - s390/cpum_sf: ensure sample frequency of perf event
    attributes is non-zero (bnc#1096753, LTC#168037).

  - s390/crypto: Adjust s390 aes and paes cipher priorities
    (bsc#1090098).

  - s390/dasd: fix IO error for newly defined devices
    (bnc#1093148, LTC#167307).

  - s390/qdio: do not merge ERROR output buffers
    (bsc#1099715).

  - s390/qdio: fix access to uninitialized qdio_q fields
    (bnc#1096753, LTC#168037).

  - s390/qeth: do not dump control cmd twice (bsc#1099715).

  - s390/qeth: fix IPA command submission race
    (bsc#1099715).

  - s390/qeth: fix IPA command submission race
    (networking-stable-18_03_07).

  - s390/qeth: fix MAC address update sequence (bnc#1093148,
    LTC#167307).

  - s390/qeth: fix overestimated count of buffer elements
    (bsc#1099715).

  - s390/qeth: fix overestimated count of buffer elements
    (networking-stable-18_03_07).

  - s390/qeth: free netdevice when removing a card
    (bsc#1099715).

  - s390/qeth: free netdevice when removing a card
    (networking-stable-18_03_28).

  - s390/qeth: lock read device while queueing next buffer
    (bsc#1099715).

  - s390/qeth: lock read device while queueing next buffer
    (networking-stable-18_03_28).

  - s390/qeth: translate SETVLAN/DELVLAN errors
    (bnc#1093148, LTC#167307).

  - s390/qeth: use Read device to query hypervisor for MAC
    (bsc#1061024 ).

  - s390/qeth: when thread completes, wake up all waiters
    (bsc#1099715).

  - s390/qeth: when thread completes, wake up all waiters
    (networking-stable-18_03_28).

  - s390/uprobes: implement arch_uretprobe_is_alive()
    (bnc#1093148, LTC#167307).

  - s390/zcrypt: Fix CCA and EP11 CPRB processing failure
    memory leak (bnc#1096753, LTC#168037).

  - s390: add automatic detection of the spectre defense
    (bsc#1090098).

  - s390: add sysfs attributes for spectre (bsc#1090098).

  - s390: correct nospec auto detection init order
    (bsc#1090098).

  - s390: move nobp parameter functions to nospec-branch.c
    (bsc#1090098).

  - s390: report spectre mitigation via syslog
    (bsc#1090098).

  - sch_netem: fix skb leak in netem_enqueue()
    (networking-stable-18_03_28).

  - sched/numa: Stagger NUMA balancing scan periods for new
    threads (Automatic NUMA Balancing ()).

  - sched/rt: Fix rq->clock_update_flags lower than
    RQCF_ACT_SKIP warning (bsc#1022476).

  - sched: Make resched_cpu() unconditional (Git-fixes).

  - sched: Stop resched_cpu() from sending IPIs to offline
    CPUs (Git-fixes).

  - sched: Stop switched_to_rt() from sending IPIs to
    offline CPUs (Git-fixes).

  - scripts/git_sort/git_sort.py :

  - scripts/git_sort/git_sort.py: Remove duplicated repo
    entry

  - scripts/git_sort/git_sort.py: add Viro's vfs git

  - scsi: core: return BLK_STS_OK for DID_OK in
    __scsi_error_from_host_byte() (bsc#1099918).

  - scsi: ipr: Format HCAM overlay ID 0x41 (bsc#1097961).

  - scsi: ipr: new IOASC update (bsc#1097961).

  - scsi: lpfc: Add per io channel NVME IO statistics
    (bsc#1088866).

  - scsi: lpfc: Change IO submit return to EBUSY if remote
    port is recovering (bsc#1088866).

  - scsi: lpfc: Comment cleanup regarding Broadcom copyright
    header (bsc#1088866).

  - scsi: lpfc: Correct fw download error message
    (bsc#1088866).

  - scsi: lpfc: Correct missing remoteport registration
    during link bounces (bsc#1088866).

  - scsi: lpfc: Correct target queue depth application
    changes (bsc#1088866).

  - scsi: lpfc: Driver NVME load fails when CPU cnt > WQ
    resource cnt (bsc#1088866).

  - scsi: lpfc: Enhance log messages when reporting CQE
    errors (bsc#1088866).

  - scsi: lpfc: Enlarge nvmet asynchronous receive buffer
    counts (bsc#1088866).

  - scsi: lpfc: Fix 16gb hbas failing cq create
    (bsc#1093290).

  - scsi: lpfc: Fix Abort request WQ selection
    (bsc#1088866).

  - scsi: lpfc: Fix MDS diagnostics failure (Rx lower than
    Tx) (bsc#1088866).

  - scsi: lpfc: Fix NULL pointer access in
    lpfc_nvme_info_show (bsc#1088866).

  - scsi: lpfc: Fix NULL pointer reference when resetting
    adapter (bsc#1088866).

  - scsi: lpfc: Fix crash in blk_mq layer when executing
    modprobe -r lpfc (bsc#1088866).

  - scsi: lpfc: Fix driver not recovering NVME rports during
    target link faults (bsc#1088866).

  - scsi: lpfc: Fix lingering lpfc_wq resource after driver
    unload (bsc#1088866).

  - scsi: lpfc: Fix multiple PRLI completion error path
    (bsc#1088866).

  - scsi: lpfc: Fix nvme remoteport registration race
    conditions (bsc#1088866).

  - scsi: lpfc: Fix port initialization failure
    (bsc#1093290).

  - scsi: lpfc: Fix up log messages and stats counters in IO
    submit code path (bsc#1088866).

  - scsi: lpfc: Handle new link fault code returned by
    adapter firmware (bsc#1088866).

  - scsi: lpfc: correct oversubscription of nvme io requests
    for an adapter (bsc#1088866).

  - scsi: lpfc: enhance LE data structure copies to hardware
    (bsc#1088866).

  - scsi: lpfc: fix spelling mistakes: 'mabilbox' and
    'maibox' (bsc#1088866).

  - scsi: lpfc: update driver version to 12.0.0.2
    (bsc#1088866).

  - scsi: lpfc: update driver version to 12.0.0.3
    (bsc#1088866).

  - scsi: lpfc: update driver version to 12.0.0.4
    (bsc#1088866).

  - scsi: qla2xxx: Add FC-NVMe abort processing
    (bsc#1084570).

  - scsi: qla2xxx: Add changes for devloss timeout in driver
    (bsc#1084570).

  - scsi: qla2xxx: Cleanup code to improve FC-NVMe error
    handling (bsc#1084570).

  - scsi: qla2xxx: Delete session for nport id change
    (bsc#1077338).

  - scsi: qla2xxx: Fix Async GPN_FT for FCP and FC-NVMe scan
    (bsc#1084570).

  - scsi: qla2xxx: Fix FC-NVMe IO abort during driver reset
    (bsc#1084570).

  - scsi: qla2xxx: Fix n2n_ae flag to prevent dev_loss on
    PDB change (bsc#1084570).

  - scsi: qla2xxx: Fix retry for PRLI RJT with reason of
    BUSY (bsc#1084570).

  - scsi: qla2xxx: Fix small memory leak in
    qla2x00_probe_one on probe failure (bsc#1077338).

  - scsi: qla2xxx: Remove nvme_done_list (bsc#1084570).

  - scsi: qla2xxx: Remove unneeded message and minor cleanup
    for FC-NVMe (bsc#1084570).

  - scsi: qla2xxx: Restore ZIO threshold setting
    (bsc#1084570).

  - scsi: qla2xxx: Return busy if rport going away
    (bsc#1084570).

  - scsi: qla2xxx: Set IIDMA and fcport state before
    qla_nvme_register_remote() (bsc#1084570).

  - scsi: qla2xxx: Update driver version to 10.00.00.06-k
    (bsc#1084570).

  - scsi: raid_class: Add 'JBOD' RAID level (bsc#1093023).

  - scsi: sg: mitigate read/write abuse (bsc#1101296).

  - scsi: target: fix crash with iscsi target and dvd
    (bsc#1099918).

  - sctp: delay the authentication for the duplicated
    cookie-echo chunk (networking-stable-18_05_15).

  - sctp: do not check port in sctp_inet6_cmp_addr
    (networking-stable-18_04_26).

  - sctp: do not leak kernel memory to user space
    (networking-stable-18_04_10).

  - sctp: do not retransmit upon FragNeeded if PMTU
    discovery is disabled (networking-stable-18_01_12).

  - sctp: fix dst refcnt leak in sctp_v6_get_dst()
    (networking-stable-18_03_07).

  - sctp: fix the handling of ICMP Frag Needed for too small
    MTUs (networking-stable-18_01_12).

  - sctp: fix the issue that the cookie-ack with auth can't
    get processed (networking-stable-18_05_15).

  - sctp: full support for ipv6 ip_nonlocal_bind and
    IP_FREEBIND (networking-stable-17_11_14).

  - sctp: handle two v4 addrs comparison in
    sctp_inet6_cmp_addr

  - sctp: potential read out of bounds in
    sctp_ulpevent_type_enabled()
    (networking-stable-17_10_09).

  - sctp: remove sctp_chunk_put from fail_mark err path in
    sctp_ulpevent_make_rcvmsg (networking-stable-18_05_15).

  - sctp: reset owner sk for data chunks on out queues when
    migrating a sock (networking-stable-17_11_14).

  - sctp: sctp_sockaddr_af must check minimal addr length
    for AF_INET6 (networking-stable-18_04_10).

  - sctp: use right member as the param of
    list_for_each_entry (git-fixes).

  - sctp: use the old asoc when making the cookie-ack chunk
    in dupcook_d (networking-stable-18_05_15).

  - sdhci: Advertise 2.0v supply on SDIO host controller
    (bsc#1051510).

  - selftests/powerpc: Fix copyloops build since Power4
    assembler change (bsc#1055117).

  - selinux: KASAN: slab-out-of-bounds in xattr_getsecurity
    (bsc#1051510).

  - selinux: ensure the context is NUL terminated in
    security_context_to_sid_core() (bsc#1051510).

  - selinux: skip bounded transition processing if the
    policy isn't loaded (bsc#1051510).

  - serdev: fix memleak on module unload (bsc#1051510).

  - serdev: fix receive_buf return value when no callback
    (bsc#1051510).

  - serdev: fix registration of second slave (bsc#1051510).

  - serdev: ttyport: add missing open() error handling
    (bsc#1051510).

  - serdev: ttyport: add missing receive_buf sanity checks
    (bsc#1051510).

  - serdev: ttyport: enforce tty-driver open() requirement
    (bsc#1051510).

  - serdev: ttyport: fix NULL-deref on hangup (bsc#1051510).

  - serdev: ttyport: fix tty locking in close (bsc#1051510).

  - serial: 8250: Preserve DLD[7:4] for PORT_XR17V35X
    (bsc#1051510).

  - serial: 8250: omap: Fix idling of clocks for unused
    uarts (bsc#1051510).

  - serial: 8250_dw: Disable clock on error (bsc#1051510).

  - serial: 8250_fintek: Fix finding base_port with
    activated SuperIO (bsc#1051510).

  - serial: 8250_pci: Add Brainboxes UC-260 4 port serial
    device (bsc#1051510).

  - serial: altera: ensure port->regshift is honored
    consistently (bsc#1051510).

  - serial: arc_uart: Fix out-of-bounds access through DT
    alias (bsc#1051510).

  - serial: core: mark port as initialized in autoconfig
    (bsc#1051510).

  - serial: fsl_lpuart: Fix out-of-bounds access through DT
    alias (bsc#1051510).

  - serial: imx: Fix out-of-bounds access through serial
    port index (bsc#1051510).

  - serial: imx: Only wakeup via RTSDEN bit if the system
    has RTS/CTS (bsc#1051510).

  - serial: mxs-auart: Fix out-of-bounds access through
    serial port index (bsc#1051510).

  - serial: omap: Fix EFR write on RTS deassertion
    (bsc#1051510).

  - serial: samsung: Fix out-of-bounds access through serial
    port index (bsc#1051510).

  - serial: samsung: fix maxburst parameter for DMA
    transactions (bsc#1051510).

  - serial: sh-sci: Fix out-of-bounds access through DT
    alias (bsc#1051510).

  - serial: sh-sci: Stop using printk format %pCr
    (bsc#1051510).

  - serial: sh-sci: prevent lockup on full TTY buffers
    (bsc#1051510).

  - serial: xuartps: Fix out-of-bounds access through DT
    alias (bsc#1051510).

  - sget(): handle failures of register_shrinker()
    (bsc#1052766).

  - sh_eth: fix SH7757 GEther initialization
    (networking-stable-18_01_12).

  - sh_eth: fix TSU resource handling
    (networking-stable-18_01_12).

  - skbuff: Fix not waking applications when errors are
    enqueued (networking-stable-18_03_28).

  - sky2: Increase D3 delay to sky2 stops working after
    suspend (bsc#1051510).

  - slip: Check if rstate is initialized before
    uncompressing (networking-stable-18_04_13).

  - sock: free skb in skb_complete_tx_timestamp on error
    (networking-stable-17_12_31).

  - soreuseport: fix mem leak in reuseport_add_sock()
    (networking-stable-18_02_06).

  - spi: Fix scatterlist elements size in spi_map_buf
    (bsc#1051510).

  - spi: a3700: Fix clk prescaling for coefficient over 15
    (bsc#1051510).

  - spi: a3700: Return correct value on timeout detection
    (bsc#1051510).

  - spi: armada-3700: Fix failing commands with quad-SPI
    (bsc#1051510).

  - spi: atmel: fixed spin_lock usage inside
    atmel_spi_remove (bsc#1051510).

  - spi: atmel: init FIFOs before spi enable (bsc#1051510).

  - spi: bcm-qspi: Fix use after free in bcm_qspi_probe() in
    error path (bsc#1051510).

  - spi: imx: do not access registers while clocks disabled
    (bsc#1051510).

  - spi: sh-msiof: Fix DMA transfer size check
    (bsc#1051510).

  - spi: spi-axi: fix potential use-after-free after
    deregistration (bsc#1051510).

  - spi: sun4i: disable clocks in the remove function
    (bsc#1051510).

  - spi: sun6i: disable/unprepare clocks on remove
    (bsc#1051510).

  - spi: xilinx: Detect stall with Unknown commands
    (bsc#1051510).

  - srcu: Provide ordering for CPU not involved in grace
    period (bsc#1052766).

  - staging: bcm2835-audio: Release resources on
    module_exit() (bsc#1051510).

  - staging: comedi: fix comedi_nsamples_left (bsc#1051510).

  - staging: comedi: ni_mio_common: ack ai fifo error
    interrupts (bsc#1051510).

  - staging: iio: ad5933: switch buffer mode to software
    (bsc#1051510).

  - staging: iio: ad7192: Fix - use the dedicated reset
    function avoiding dma from stack (bsc#1051510).

  - staging: iio: adc: ad7192: fix external frequency
    setting (bsc#1051510).

  - staging: rtl8192u: return -ENOMEM on failed allocation
    of priv->oldaddr (bsc#1051510).

  - staging: vchiq_2835_arm: Fix NULL ptr dereference in
    free_pagelist (bsc#1051510).

  - staging: wilc1000: Fix bssid buffer offset in Txq
    (bsc#1051510).

  - stm class: Fix a use-after-free (bsc#1051510).

  - stm class: Use vmalloc for the master map (bsc#1051510).

  - stmmac: reset last TSO segment size after device open
    (networking-stable-17_12_12).

  - strparser: Do not call mod_delayed_work with a timeout
    of LONG_MAX (networking-stable-18_04_26).

  - strparser: Fix incorrect strp->need_bytes value
    (networking-stable-18_04_26).

  - strparser: Fix sign of err codes
    (networking-stable-18_04_10).

  - sunrpc: remove incorrect HMAC request initialization
    (bsc#1051510).

  - supported.conf: Remove external flag from iwlwifi
    modules (bsc#1093273)

  - supported.conf: add arch/s390/crypto/crc32-vx_s390
    (bsc#1089889).

  - supported.conf: fix folder of the driver module

  - supported.conf: mark new FIPS modules as supported:
    sha2-mb, sha3, crc32 and crypto_engine (bsc#1074984)

  - supported.conf: remove obsolete entry
    drivers/tty/serial/of_serial ->
    drivers/tty/serial/8250/8250_of

  - swap: divide-by-zero when zero length swap file on ssd
    (bsc#1051510).

  - swiotlb: suppress warning when __GFP_NOWARN is set
    (bsc#1051510).

  - tap: reference to KVA of an unloaded module causes
    kernel panic (networking-stable-17_11_14).

  - target: transport should handle st FM/EOM/ILI reads
    (bsc#1081599).

  - tcp: do not read out-of-bounds opsize
    (networking-stable-18_04_26).

  - tcp: fix data delivery rate
    (networking-stable-17_10_09).

  - tcp: ignore Fast Open on repair mode
    (networking-stable-18_05_15).

  - tcp: md5: reject TCP_MD5SIG or TCP_MD5SIG_EXT on
    established sockets (networking-stable-18_04_26).

  - tcp: release sk_frag.page in tcp_disconnect
    (networking-stable-18_02_06).

  - tcp: revert F-RTO extension to detect more spurious
    timeouts (networking-stable-18_03_07).

  - tcp: revert F-RTO middle-box workaround (bsc#1076830).

  - tcp_bbr: fix to zero idle_restart only upon S/ACKed data
    (networking-stable-18_05_15).

  - tcp_bbr: record 'full bw reached' decision in new
    full_bw_reached bit (networking-stable-17_12_31).

  - tcp_bbr: reset full pipe detection on loss recovery undo
    (networking-stable-17_12_31).

  - tcp_bbr: reset long-term bandwidth sampling on loss
    recovery undo (networking-stable-17_12_31).

  - tcp_nv: fix division by zero in tcpnv_acked()
    (networking-stable-17_11_20).

  - team: Fix double free in error path
    (networking-stable-18_03_28).

  - team: avoid adding twice the same option to the event
    list (networking-stable-18_04_26).

  - team: fix netconsole setup over team
    (networking-stable-18_04_26).

  - team: move dev_mc_sync after master_upper_dev_link in
    team_port_add (networking-stable-18_04_10).

  - tee: check shm references are consistent in offset/size
    (bsc#1051510).

  - tee: shm: fix use-after-free via temporarily dropped
    reference (bsc#1051510).

  - test_firmware: fix missing unlock on error in
    config_num_requests_store() (bsc#1051510).

  - test_firmware: fix setting old custom fw path back on
    exit (bsc#1051510).

  - test_firmware: fix setting old custom fw path back on
    exit, second try (bsc#1051510).

  - tg3: APE heartbeat changes (bsc#1086286 ).

  - tg3: Add Macronix NVRAM support (bsc#1086286 ).

  - tg3: Fix vunmap() BUG_ON() triggered from
    tg3_free_consistent() (bsc#1086286 ).

  - tg3: prevent scheduling while atomic splat (bsc#1086286
    ).

  - thermal/drivers/step_wise: Fix temperature regulation
    misbehavior (bsc#1051510).

  - thermal: bcm2835: Stop using printk format %pCr
    (bsc#1051510).

  - thermal: enable broadcom menu for arm64 bcm2835
    (bsc#1095573).

  - thermal: exynos: Propagate error value from tmu_read()
    (bsc#1051510).

  - thermal: exynos: Reading temperature makes sense only
    when TMU is turned on (bsc#1051510).

  - thermal: imx: Fix race condition in imx_thermal_probe()
    (bsc#1051510).

  - thermal: int3400_thermal: fix error handling in
    int3400_thermal_probe() (bsc#1051510).

  - thermal: int3403_thermal: Fix NULL pointer deref on
    module load / probe (bsc#1051510).

  - thermal: power_allocator: fix one race condition issue
    for thermal_instances list (bsc#1051510).

  - thunderbolt: Prevent crash when ICM firmware is not
    running (bsc#1090888).

  - thunderbolt: Resume control channel after hibernation
    image is created (bsc#1051510).

  - thunderbolt: Serialize PCIe tunnel creation with PCI
    rescan (bsc#1090888).

  - thunderbolt: Wait a bit longer for ICM to authenticate
    the active NVM (bsc#1090888).

  - timekeeping: Eliminate the stale declaration of
    ktime_get_raw_and_real_ts64() (bsc#1099918).

  - timers: Invoke timer_start_debug() where it makes sense
    (Git-fixes).

  - timers: Reinitialize per cpu bases on hotplug
    (Git-fixes).

  - timers: Unconditionally check deferrable base
    (Git-fixes).

  - timers: Use deferrable base independent of
    base::nohz_active (Git-fixes).

  - tipc: add policy for TIPC_NLA_NET_ADDR
    (networking-stable-18_04_26).

  - tipc: fix a memory leak in tipc_nl_node_get_link()
    (networking-stable-18_01_28).

  - tipc: fix hanging poll() for stream sockets
    (networking-stable-17_12_31).

  - tipc: fix memory leak in tipc_accept_from_sock()
    (networking-stable-17_12_12).

  - tools headers: Restore READ_ONCE() C++ compatibility
    (bsc#1093023).

  - tools/lib/subcmd/pager.c: do not alias select() params
    (Fix gcc 8 restrict error).

  - tracing/uprobe_event: Fix strncpy corner case
    (bsc#1099918).

  - tracing: Fix converting enum's from the map in
    trace_event_eval_update() (bsc#1099918).

  - tracing: Fix missing tab for hwlat_detector print format
    (bsc#1099918).

  - tracing: Kconfig text fixes for CONFIG_HWLAT_TRACER
    (bsc#1099918).

  - tracing: Make the snapshot trigger work with instances
    (bsc#1099918).

  - tracing: probeevent: Fix to support minus offset from
    symbol (bsc#1099918).

  - tty fix oops when rmmod 8250 (bsc#1051510).

  - tty/serial: atmel: add new version check for usart
    (bsc#1051510).

  - tty/serial: atmel: use port->name as name in
    request_irq() (bsc#1051510).

  - tty: Avoid possible error pointer dereference at
    tty_ldisc_restore() (bsc#1051510).

  - tty: Do not call panic() at tty_ldisc_init()
    (bsc#1051510).

  - tty: Use __GFP_NOFAIL for tty_ldisc_get() (bsc#1051510).

  - tty: fix __tty_insert_flip_char regression
    (bsc#1051510).

  - tty: fix tty_ldisc_receive_buf() documentation
    (bsc#1051510).

  - tty: improve tty_insert_flip_char() fast path
    (bsc#1051510).

  - tty: improve tty_insert_flip_char() slow path
    (bsc#1051510).

  - tty: make n_tty_read() always abort if hangup is in
    progress (bsc#1051510).

  - tty: n_gsm: Allow ADM response in addition to UA for
    control dlci (bsc#1051510).

  - tty: n_gsm: Fix DLCI handling for ADM mode if debug and
    2 is not set (bsc#1051510).

  - tty: n_gsm: Fix long delays with control frame timeouts
    in ADM mode (bsc#1051510).

  - tty: pl011: Avoid spuriously stuck-off interrupts
    (bsc#1051510).

  - tty: vt: fix up tabstops properly (bsc#1051510).

  - tun/tap: sanitize TUNSETSNDBUF input
    (networking-stable-17_11_14).

  - tun: allow positive return values on
    dev_get_valid_name() call (networking-stable-17_11_14).

  - tun: bail out from tun_get_user() if the skb is empty
    (networking-stable-17_10_09).

  - tun: call dev_get_valid_name() before
    register_netdevice() (networking-stable-17_11_14).

  - ubi: Fix error for write access (bsc#1051510).

  - ubi: Fix race condition between ubi volume creation and
    udev (bsc#1051510).

  - ubi: Reject MLC NAND (bsc#1051510).

  - ubi: block: Fix locking for idr_alloc/idr_remove
    (bsc#1051510).

  - ubi: fastmap: Cancel work upon detach (bsc#1051510).

  - ubi: fastmap: Cancel work upon detach (bsc#1051510).

  - ubi: fastmap: Do not flush fastmap work on detach
    (bsc#1051510).

  - ubi: fastmap: Erase outdated anchor PEBs during attach
    (bsc#1051510).

  - ubifs: Check ubifs_wbuf_sync() return code
    (bsc#1052766).

  - ubifs: free the encrypted symlink target (bsc#1052766).

  - udf: Avoid overflow when session starts at large offset
    (bsc#1052766).

  - udf: Fix leak of UTF-16 surrogates into encoded strings
    (bsc#1052766).

  - usb: core: Add quirk for HP v222w 16GB Mini
    (bsc#1090888).

  - usb: quirks: add control message delay for 1b1c:1b20
    (bsc#1087092).

  - usb: typec: ucsi: Fix for incorrect status data issue
    (bsc#1100132).

  - usb: typec: ucsi: Increase command completion timeout
    value (bsc#1090888).

  - usb: typec: ucsi: acpi: Workaround for cache mode issue
    (bsc#1100132).

  - usb: xhci: Disable slot even when virt-dev is null
    (bsc#1085539).

  - usb: xhci: Fix potential memory leak in
    xhci_disable_slot() (bsc#1085539).

  - usb: xhci: Make some static functions global ().

  - usbip: usbip_host: delete device from busid_table after
    rebind (bsc#1096480).

  - usbip: usbip_host: fix NULL-ptr deref and use-after-free
    errors (bsc#1096480).

  - usbip: usbip_host: fix bad unlock balance during
    stub_probe() (bsc#1096480).

  - usbip: usbip_host: fix to hold parent lock for
    device_attach() calls (bsc#1096480).

  - usbip: usbip_host: run rebind from exit when module is
    removed (bsc#1096480).

  - usbip: vudc: fix NULL pointer dereference on udc->lock
    (bsc#1087092).

  - userns: Do not fail follow_automount based on s_user_ns
    (bsc#1099918).

  - vfb: fix video mode and line_length being set when
    loaded (bsc#1100362).

  - vfio: Use get_user_pages_longterm correctly
    (bsc#1095337).

  - vfio: disable filesystem-dax page pinning (bsc#1095337).

  - vfio: platform: Fix reset module leak in error path
    (bsc#1099918).

  - vhost: Fix vhost_copy_to_user()
    (networking-stable-18_04_13).

  - vhost: correctly remove wait queue during poll failure
    (networking-stable-18_04_10).

  - vhost: fix vhost_vq_access_ok() log check
    (networking-stable-18_04_13).

  - vhost: validate log when IOTLB is enabled
    (networking-stable-18_04_10).

  - vhost_net: add missing lock nesting notation
    (networking-stable-18_04_10).

  - vhost_net: stop device during reset owner
    (networking-stable-18_02_06).

  - video/fbdev/stifb: Return -ENOMEM after a failed
    kzalloc() in stifb_init_fb() (bsc#1090888 bsc#1099966).

  - video/hdmi: Allow 'empty' HDMI infoframes (bsc#1051510).

  - video: fbdev/mmp: add MODULE_LICENSE (bsc#1051510).

  - video: fbdev: atmel_lcdfb: fix display-timings lookup
    (bsc#1051510).

  - video: fbdev: aty: do not leak uninitialized padding in
    clk to userspace (bsc#1051510).

  - video: fbdev: au1200fb: Release some resources if a
    memory allocation fails (bsc#1051510).

  - video: fbdev: au1200fb: Return an error code if a memory
    allocation fails (bsc#1051510).

  - virtio-gpu: fix ioctl and expose the fixed status to
    userspace (bsc#1100382).

  - virtio: add ability to iterate over vqs (bsc#1051510).

  - virtio: release virtio index when fail to
    device_register (bsc#1051510).

  - virtio_console: do not tie bufs to a vq (bsc#1051510).

  - virtio_console: drop custom control queue cleanup
    (bsc#1051510).

  - virtio_console: free buffers after reset (bsc#1051510).

  - virtio_console: move removal code (bsc#1051510).

  - virtio_console: reset on out of memory (bsc#1051510).

  - virtio_net: fix adding vids on big-endian
    (networking-stable-18_04_26).

  - virtio_net: fix return value check in
    receive_mergeable() (bsc#1089271).

  - virtio_net: split out ctrl buffer
    (networking-stable-18_04_26).

  - virtio_ring: fix num_free handling in error case
    (bsc#1051510).

  - vlan: Fix reading memory beyond skb->tail in
    skb_vlan_tagged_multi (networking-stable-18_04_26).

  - vlan: also check phy_driver ts_info for vlan's real
    device (networking-stable-18_04_10).

  - vlan: fix a use-after-free in vlan_device_event()
    (networking-stable-17_11_20).

  - vmw_balloon: fix inflation with batching (bsc#1051510).

  - vmw_balloon: fixing double free when batching mode is
    off (bsc#1051510).

  - vmxnet3: avoid xmit reset due to a race in vmxnet3
    (bsc#1091860).

  - vmxnet3: fix incorrect dereference when rxvlan is
    disabled (bsc#1091860).

  - vmxnet3: increase default rx ring sizes (bsc#1091860).

  - vmxnet3: repair memory leak (bsc#1051510).

  - vmxnet3: set the DMA mask before the first DMA map
    operation (bsc#1091860).

  - vmxnet3: use DMA memory barriers where required
    (bsc#1091860).

  - vmxnet3: use correct flag to indicate LRO feature
    (bsc#1091860).

  - vrf: Fix use after free and double free in
    vrf_finish_output (networking-stable-18_04_10).

  - vt6655: Fix a possible sleep-in-atomic bug in
    vt6655_suspend (bsc#1051510).

  - vt: change SGR 21 to follow the standards (bsc#1051510).

  - vt: prevent leaking uninitialized data to userspace via
    /dev/vcs* (bsc#1051510).

  - vti6: Change minimum MTU to IPV4_MIN_MTU, vti6 can carry
    IPv4 too (bsc#1082869).

  - vti6: Fix dev->max_mtu setting (bsc#1082869).

  - vti6: Keep set MTU on link creation or change, validate
    it (bsc#1082869).

  - vti6: Properly adjust vti6 MTU from MTU of lower device
    (bsc#1082869).

  - vti6: better validate user provided tunnel names
    (networking-stable-18_04_10).

  - vti: fix use after free in vti_tunnel_xmit/vti6_tnl_xmit
    (bsc#1076830).

  - vxlan: fix the issue that neigh proxy blocks all icmpv6
    packets (networking-stable-17_11_20).

  - w1: mxc_w1: Enable clock before calling clk_get_rate()
    on it (bsc#1051510).

  - wait: add wait_event_killable_timeout() (bsc#1099792).

  - watchdog: da9063: Fix setting/changing timeout
    (bsc#1100843).

  - watchdog: da9063: Fix timeout handling during probe
    (bsc#1100843).

  - watchdog: da9063: Fix updating timeout value
    (bsc#1100843).

  - watchdog: f71808e_wdt: Fix WD_EN register read
    (bsc#1051510).

  - watchdog: f71808e_wdt: Fix magic close handling
    (bsc#1051510).

  - watchdog: sp5100_tco: Fix watchdog disable bit
    (bsc#1051510).

  - wcn36xx: Fix dynamic power saving (bsc#1051510).

  - wcn36xx: Introduce mutual exclusion of fw configuration
    (bsc#1051510).

  - wl1251: check return from call to
    wl1251_acx_arp_ip_filter (bsc#1051510).

  - workqueue: Allow retrieval of current task's work struct
    (bsc#1051510).

  - workqueue: use put_device() instead of kfree()
    (bsc#1051510).

  - x86,sched: Allow topologies where NUMA nodes share an
    LLC (bsc#1091158).

  - x86/cpu_entry_area: Map also trace_idt_table
    (bsc#1089878).

  - x86/cpuinfo: Ignore ->initialized member (bsc#1091543).

  - x86/intel_rdt: Add command line parameter to control
    L2_CDP ().

  - x86/intel_rdt: Add two new resources for L2 Code and
    Data Prioritization (CDP) ().

  - x86/intel_rdt: Enable L2 CDP in MSR IA32_L2_QOS_CFG ().

  - x86/intel_rdt: Enumerate L2 Code and Data Prioritization
    (CDP) feature ().

  - x86/mm/64: Fix vmapped stack syncing on
    very-large-memory 4-level systems (bsc#1088374).

  - x86/mm: add a function to check if a pfn is UC/UC-/WC
    (bsc#1087213).

  - x86/pkeys: Add arch_pkeys_enabled() (bsc#1078248).

  - x86/pkeys: Move vma_pkey() into asm/pkeys.h
    (bsc#1078248).

  - x86/pti: do not report XenPV as vulnerable
    (bsc#1097551).

  - x86/setup: Do not reserve a crash kernel region if
    booted on Xen PV (bsc#1085626).

  - x86/smpboot: Do not use smp_num_siblings in
    __max_logical_packages calculation (bsc#1091543).

  - x86/smpboot: Fix __max_logical_packages estimate
    (bsc#1091543).

  - x86/smpboot: Fix uncore_pci_remove() indexing bug when
    hot-removing a physical CPU (bsc#1091543).

  - x86/stacktrace: Clarify the reliable success paths
    (bnc#1058115).

  - x86/stacktrace: Do not fail for ORC with regs on stack
    (bnc#1058115).

  - x86/stacktrace: Do not unwind after user regs
    (bnc#1058115).

  - x86/stacktrace: Enable HAVE_RELIABLE_STACKTRACE for the
    ORC unwinder (bnc#1058115).

  - x86/stacktrace: Remove STACKTRACE_DUMP_ONCE
    (bnc#1058115).

  - x86/topology: Avoid wasting 128k for package id array
    (bsc#1091543).

  - x86/tsc: Future-proof native_calibrate_tsc()
    (bsc#1074873).

  - x86/unwind/orc: Detect the end of the stack
    (bnc#1058115).

  - x86/xen: Calculate __max_logical_packages on PV domains
    (bsc#1091543).

  - xen/acpi: off by one in read_acpi_id() (bnc#1065600).

  - xen/netfront: raise max number of slots in
    xennet_get_responses() (bnc#1076049).

  - xen/vcpu: Handle xen_vcpu_setup() failure at boot
    (bsc#1091543).

  - xen: do not print error message in case of missing
    Xenstore entry (bnc#1065600).

  - xfs: allow CoW remap transactions to use reserve blocks
    (bsc#1090535).

  - xfs: convert XFS_AGFL_SIZE to a helper function
    (bsc#1090534).

  - xfs: detect agfl count corruption and reset agfl
    (bsc#1090534).

  - xfs: fix intent use-after-free on abort (bsc#1085400).

  - xfs: fix transaction allocation deadlock in IO path
    (bsc#1090535).

  - xhci: Add port status decoder for tracing purposes ().

  - xhci: Fix USB ports for Dell Inspiron 5775
    (bsc#1090888).

  - xhci: add definitions for all port link states ().

  - xhci: add port speed ID to portsc tracing ().

  - xhci: add port status tracing ().

  - xhci: fix endpoint context tracer output (bsc#1087092).

  - xhci: workaround for AMD Promontory disabled ports
    wakeup (bsc#1087092).

  - xhci: zero usb device slot_id member when disabling and
    freeing a xhci slot (bsc#1090888).

  - xprtrdma: Fix corner cases when handling device removal
    (git-fixes).

  - xprtrdma: Fix list corruption / DMAR errors during MR
    recovery

  - xprtrdma: Return -ENOBUFS when no pages are available"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064802"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975772"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.7.1") ) flag++;

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
