#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2444.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(130582);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-16232", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16995", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-2444)");
  script_summary(english:"Check for the openSUSE-2019-2444 patch");

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

  - CVE-2019-16995: A memory leak exits in
    hsr_dev_finalize() in net/hsr/hsr_device.c. if
    hsr_add_port fails to add a port, which may cause denial
    of service, aka CID-6caabe7f197d (bnc#1152685).

  - CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150457).

  - CVE-2019-17666: rtl_p2p_noa_ie in
    drivers/net/wireless/realtek/rtlwifi/ps.c lacked a
    certain upper-bound check, leading to a buffer overflow
    (bnc#1154372).

  - CVE-2019-16232:
    drivers/net/wireless/marvell/libertas/if_sdio.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150465).

  - CVE-2019-16234:
    drivers/net/wireless/intel/iwlwifi/pcie/trans.c did not
    check the alloc_workqueue return value, leading to a
    NULL pointer dereference (bnc#1150452).

  - CVE-2019-17133: cfg80211_mgd_wext_giwessid in
    net/wireless/wext-sme.c did not reject a long SSID IE,
    leading to a Buffer Overflow (bnc#1153158).

  - CVE-2019-17056: llcp_sock_create in net/nfc/llcp_sock.c
    in the AF_NFC network module did not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka CID-3a359798b176 (bnc#1152788).

The following non-security bugs were fixed :

  - 9p: avoid attaching writeback_fid on mmap with type
    PRIVATE (bsc#1051510).

  - ACPI / CPPC: do not require the _PSD method
    (bsc#1051510).

  - ACPI: CPPC: Set pcc_data[pcc_ss_id] to NULL in
    acpi_cppc_processor_exit() (bsc#1051510).

  - ACPI / processor: do not print errors for processorIDs
    == 0xff (bsc#1051510).

  - act_mirred: Fix mirred_init_module error handling
    (bsc#1051510).

  - Add Acer Aspire Ethos 8951G model quirk (bsc#1051510).

  - Add kernel module compression support (bsc#1135854)

  - ALSA: hda - Add a quirk model for fixing Huawei Matebook
    X right speaker (bsc#1051510).

  - ALSA: hda: Add Elkhart Lake PCI ID (bsc#1051510).

  - ALSA: hda - Add laptop imic fixup for ASUS M9V laptop
    (bsc#1051510).

  - ALSA: hda: Add support of Zhaoxin controller
    (bsc#1051510).

  - ALSA: hda: Add Tigerlake/Jasperlake PCI ID
    (bsc#1051510).

  - ALSA: hda - Apply AMD controller workaround for Raven
    platform (bsc#1051510).

  - ALSA: hda - Define a fallback_pin_fixup_tbl for alc269
    family (bsc#1051510).

  - ALSA: hda - Drop unsol event handler for Intel HDMI
    codecs (bsc#1051510).

  - ALSA: hda - Expand pin_match function to match upcoming
    new tbls (bsc#1051510).

  - ALSA: hda: Flush interrupts on disabling (bsc#1051510).

  - ALSA: hda - Force runtime PM on Nvidia HDMI codecs
    (bsc#1051510).

  - ALSA: hda/hdmi - Do not report spurious jack state
    changes (bsc#1051510).

  - ALSA: hda/hdmi: remove redundant assignment to variable
    pcm_idx (bsc#1051510).

  - ALSA: hda - Inform too slow responses (bsc#1051510).

  - ALSA: hda/realtek - Add support for ALC711
    (bsc#1051510).

  - ALSA: hda/realtek - Blacklist PC beep for Lenovo
    ThinkCentre M73/93 (bsc#1051510).

  - ALSA: hda/realtek - Check beep whitelist before
    assigning in all codecs (bsc#1051510).

  - ALSA: hda/realtek - Enable headset mic on Asus MJ401TA
    (bsc#1051510).

  - ALSA: hda/realtek - Fix alienware headset mic
    (bsc#1051510).

  - ALSA: hda/realtek - PCI quirk for Medion E4254
    (bsc#1051510).

  - ALSA: hda/realtek: Reduce the Headphone static noise on
    XPS 9350/9360 (bsc#1051510).

  - ALSA: hda: Set fifo_size for both playback and capture
    streams (bsc#1051510).

  - ALSA: hda - Show the fatal CORB/RIRB error more clearly
    (bsc#1051510).

  - ALSA: hda/sigmatel - remove unused variable
    'stac9200_core_init' (bsc#1051510).

  - ALSA: i2c: ak4xxx-adda: Fix a possible NULL pointer
    dereference in build_adc_controls() (bsc#1051510).

  - ALSA: line6: sizeof (byte) is always 1, use that fact
    (bsc#1051510).

  - ALSA: usb-audio: Add DSD support for EVGA NU Audio
    (bsc#1051510).

  - ALSA: usb-audio: Add Hiby device family to quirks for
    native DSD support (bsc#1051510).

  - ALSA: usb-audio: Add Pioneer DDJ-SX3 PCM quirck
    (bsc#1051510).

  - ALSA: usb-audio: Clean up check_input_term()
    (bsc#1051510).

  - ALSA: usb-audio: Disable quirks for BOSS Katana
    amplifiers (bsc#1051510).

  - ALSA: usb-audio: DSD auto-detection for Playback Designs
    (bsc#1051510).

  - ALSA: usb-audio: fix PCM device order (bsc#1051510).

  - ALSA: usb-audio: Fix possible NULL dereference at
    create_yamaha_midi_quirk() (bsc#1051510).

  - ALSA: usb-audio: More validations of descriptor units
    (bsc#1051510).

  - ALSA: usb-audio: remove some dead code (bsc#1051510).

  - ALSA: usb-audio: Remove superfluous bLength checks
    (bsc#1051510).

  - ALSA: usb-audio: Simplify parse_audio_unit()
    (bsc#1051510).

  - ALSA: usb-audio: Skip bSynchAddress endpoint check if it
    is invalid (bsc#1051510).

  - ALSA: usb-audio: Unify audioformat release code
    (bsc#1051510).

  - ALSA: usb-audio: Unify the release of
    usb_mixer_elem_info objects (bsc#1051510).

  - ALSA: usb-audio: Update DSD support quirks for Oppo and
    Rotel (bsc#1051510).

  - appletalk: enforce CAP_NET_RAW for raw sockets
    (bsc#1051510).

  - arcnet: provide a buffer big enough to actually receive
    packets (networking-stable-19_09_30).

  - ASoC: Define a set of DAPM pre/post-up events
    (bsc#1051510).

  - ASoC: dmaengine: Make the pcm->name equal to pcm->id if
    the name is not set (bsc#1051510).

  - ASoC: Intel: Fix use of potentially uninitialized
    variable (bsc#1051510).

  - ASoC: Intel: NHLT: Fix debug print format (bsc#1051510).

  - ASoc: rockchip: i2s: Fix RPM imbalance (bsc#1051510).

  - ASoC: rsnd: Reinitialize bit clock inversion flag for
    every format setting (bsc#1051510).

  - ASoC: sgtl5000: Fix charge pump source assignment
    (bsc#1051510).

  - auxdisplay: panel: need to delete scan_timer when
    misc_register fails in panel_attach (bsc#1051510).

  - ax25: enforce CAP_NET_RAW for raw sockets (bsc#1051510).

  - Blacklist 'signal: Correct namespace fixups of si_pid
    and si_uid' (bsc#1142667)

  - blk-wbt: abstract out end IO completion handler
    (bsc#1135873).

  - blk-wbt: fix has-sleeper queueing check (bsc#1135873).

  - blk-wbt: improve waking of tasks (bsc#1135873).

  - blk-wbt: move disable check into get_limit()
    (bsc#1135873).

  - blk-wbt: use wq_has_sleeper() for wq active check
    (bsc#1135873).

  - block: add io timeout to sysfs (bsc#1148410).

  - block: add io timeout to sysfs (bsc#1148410).

  - block: do not show io_timeout if driver has no timeout
    handler (bsc#1148410).

  - block: do not show io_timeout if driver has no timeout
    handler (bsc#1148410).

  - bluetooth: btrtl: Additional Realtek 8822CE Bluetooth
    devices (bsc#1051510).

  - bnx2x: Fix VF's VLAN reconfiguration in reload
    (bsc#1086323 ).

  - bnxt_en: Add PCI IDs for 57500 series NPAR devices
    (bsc#1153607).

  - bpf: fix use after free in prog symbol exposure
    (bsc#1083647).

  - bridge/mdb: remove wrong use of NLM_F_MULTI
    (networking-stable-19_09_15).

  - btrfs: bail out gracefully rather than BUG_ON
    (bsc#1153646).

  - btrfs: block-group: Fix a memory leak due to missing
    btrfs_put_block_group() (bsc#1155178).

  - btrfs: check for the full sync flag while holding the
    inode lock during fsync (bsc#1153713).

  - btrfs: Ensure btrfs_init_dev_replace_tgtdev sees up to
    date values (bsc#1154651).

  - btrfs: Ensure replaced device does not have pending
    chunk allocation (bsc#1154607).

  - btrfs: qgroup: Always free PREALLOC META reserve in
    btrfs_delalloc_release_extents() (bsc#1155179).

  - btrfs: remove wrong use of volume_mutex from
    btrfs_dev_replace_start (bsc#1154651).

  - btrfs: tracepoints: Fix bad entry members of qgroup
    events (bsc#1155186).

  - btrfs: tracepoints: Fix wrong parameter order for qgroup
    events (bsc#1155184).

  - can: mcp251x: mcp251x_hw_reset(): allow more time after
    a reset (bsc#1051510).

  - can: xilinx_can: xcan_probe(): skip error message on
    deferred probe (bsc#1051510).

  - cdc_ether: fix rndis support for Mediatek based
    smartphones (networking-stable-19_09_15).

  - cdc_ncm: fix divide-by-zero caused by invalid
    wMaxPacketSize (bsc#1051510).

  - ceph: fix directories inode i_blkbits initialization
    (bsc#1153717).

  - ceph: reconnect connection if session hang in opening
    state (bsc#1153718).

  - ceph: update the mtime when truncating up (bsc#1153719).

  - cfg80211: add and use strongly typed element iteration
    macros (bsc#1051510).

  - cfg80211: Purge frame registrations on iftype change
    (bsc#1051510).

  - clk: at91: select parent if main oscillator or bypass is
    enabled (bsc#1051510).

  - clk: qoriq: Fix -Wunused-const-variable (bsc#1051510).

  - clk: sirf: Do not reference clk_init_data after
    registration (bsc#1051510).

  - clk: zx296718: Do not reference clk_init_data after
    registration (bsc#1051510).

  - crypto: af_alg - consolidation of duplicate code
    (bsc#1154737).

  - crypto: af_alg - fix race accessing cipher request
    (bsc#1154737).

  - crypto: af_alg - Fix race around ctx->rcvused by making
    it atomic_t (bsc#1154737).

  - crypto: af_alg - Initialize sg_num_bytes in error code
    path (bsc#1051510).

  - crypto: af_alg - remove locking in async callback
    (bsc#1154737).

  - crypto: af_alg - update correct dst SGL entry
    (bsc#1051510).

  - crypto: af_alg - wait for data at beginning of recvmsg
    (bsc#1154737).

  - crypto: algif_aead - copy AAD from src to dst
    (bsc#1154737).

  - crypto: algif_aead - fix reference counting of null
    skcipher (bsc#1154737).

  - crypto: algif_aead - overhaul memory management
    (bsc#1154737).

  - crypto: algif_aead - skip SGL entries with NULL page
    (bsc#1154737).

  - crypto: algif - return error code when no data was
    processed (bsc#1154737).

  - crypto: algif_skcipher - overhaul memory management
    (bsc#1154737).

  - crypto: talitos - fix missing break in switch statement
    (bsc#1142635).

  - cxgb4: do not dma memory off of the stack (bsc#1152790).

  - cxgb4: fix endianness for vlan value in cxgb4_tc_flower
    (bsc#1064802 bsc#1066129).

  - cxgb4:Fix out-of-bounds MSI-X info array access
    (networking-stable-19_10_05).

  - cxgb4: offload VLAN flows regardless of VLAN ethtype
    (bsc#1064802 bsc#1066129).

  - cxgb4: reduce kernel stack usage in
    cudbg_collect_mem_region() (bsc#1073513).

  - cxgb4: Signedness bug in init_one() (bsc#1097585
    bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583
    bsc#1097584).

  - cxgb4: smt: Add lock for atomic_dec_and_test
    (bsc#1064802 bsc#1066129).

  - dasd_fba: Display '00000000' for zero page when dumping
    sense

  - /dev/mem: Bail out upon SIGKILL (git-fixes).

  - drm: add __user attribute to ptr_to_compat()
    (bsc#1111666).

  - drm/amd/display: fix issue where 252-255 values are
    clipped (bsc#1111666).

  - drm/amd/display: reprogram VM config when system resume
    (bsc#1111666).

  - drm/amd/display: Restore backlight brightness after
    system resume (bsc#1112178)

  - drm/amd/display: support spdif (bsc#1111666).

  - drm/amd/dm: Understand why attaching path/tile
    properties are needed (bsc#1111666).

  - drm/amdgpu: Check for valid number of registers to read
    (bsc#1051510).

  - drm/amdgpu: Fix KFD-related kernel oops on Hawaii
    (bsc#1111666).

  - drm/amdgpu/gfx9: Update gfx9 golden settings
    (bsc#1111666).

  - drm/amdgpu/si: fix ASIC tests (git-fixes).

  - drm/amdgpu: Update gc_9_0 golden settings (bsc#1111666).

  - drm/amdkfd: Add missing Polaris10 ID (bsc#1111666).

  - drm/amd/powerplay/smu7: enforce minimal VBITimeout (v2)
    (bsc#1051510).

  - drm/amd/pp: Fix truncated clock value when set watermark
    (bsc#1111666).

  - drm/ast: Fixed reboot test may cause system hanged
    (bsc#1051510).

  - drm/atomic_helper: Allow DPMS On<->Off changes for
    unregistered connectors (bsc#1111666).

  - drm/atomic_helper: Disallow new modesets on unregistered
    connectors (bsc#1111666).

  - drm/atomic_helper: Stop modesets on unregistered
    connectors harder (bsc#1111666).

  - drm/bridge: tc358767: Increase AUX transfer length limit
    (bsc#1051510).

  - drm/bridge: tfp410: fix memleak in get_modes()
    (bsc#1111666).

  - drm/edid: Add 6 bpc quirk for SDC panel in Lenovo G50
    (bsc#1051510).

  - drm: Flush output polling on shutdown (bsc#1051510).

  - drm/i915: Cleanup gt powerstate from gem (bsc#1111666).

  - drm/i915: Fix intel_dp_mst_best_encoder() (bsc#1111666).

  - drm/i915/gvt: update vgpu workload head pointer
    correctly (bsc#1112178)

  - drm/i915: Restore sane defaults for KMS on GEM error
    load (bsc#1111666).

  - drm/mediatek: set DMA max segment size (bsc#1111666).

  - drm/msm/dsi: Fix return value check for clk_get_parent
    (bsc#1111666).

  - drm/msm/dsi: Implement reset correctly (bsc#1051510).

  - drm/nouveau/disp/nv50-: fix center/aspect-corrected
    scaling (bsc#1111666).

  - drm/nouveau/kms/nv50-: Do not create MSTMs for eDP
    connectors (bsc#1112178)

  - drm/nouveau/volt: Fix for some cards having 0 maximum
    voltage (bsc#1111666).

  - drm/omap: fix max fclk divider for omap36xx
    (bsc#1111666).

  - drm/panel: check failure cases in the probe func
    (bsc#1111666).

  - drm/panel: make drm_panel.h self-contained
    (bsc#1111666).

  - drm: panel-orientation-quirks: Add extra quirk table
    entry for GPD MicroPC (bsc#1111666).

  - drm/panel: simple: fix AUO g185han01 horizontal blanking
    (bsc#1051510).

  - drm/radeon: Bail earlier when radeon.cik_/si_support=0
    is passed (bsc#1111666).

  - drm/radeon: Fix EEH during kexec (bsc#1051510).

  - drm: rcar-du: lvds: Fix bridge_to_rcar_lvds
    (bsc#1111666).

  - drm/rockchip: Check for fast link training before
    enabling psr (bsc#1111666).

  - drm/stm: attach gem fence to atomic state (bsc#1111666).

  - drm/tilcdc: Register cpufreq notifier after we have
    initialized crtc (bsc#1051510).

  - drm/vmwgfx: Fix double free in vmw_recv_msg()
    (bsc#1051510).

  - e1000e: add workaround for possible stalled packet
    (bsc#1051510).

  - efi/arm: Show SMBIOS bank/device location in CPER and
    GHES error logs (bsc#1152033).

  - efi: cper: print AER info of PCIe fatal error
    (bsc#1051510).

  - efi/memattr: Do not bail on zero VA if it equals the
    region's PA (bsc#1051510).

  - efivar/ssdt: Do not iterate over EFI vars if no SSDT
    override was specified (bsc#1051510).

  - firmware: dmi: Fix unlikely out-of-bounds read in
    save_mem_devices (git-fixes).

  - Fix AMD IOMMU kABI (bsc#1154610).

  - Fix KVM kABI after x86 mmu backports (bsc#1117665).

  - gpu: drm: radeon: Fix a possible NULL pointer
    dereference in radeon_connector_set_property()
    (bsc#1051510).

  - HID: apple: Fix stuck function keys when using FN
    (bsc#1051510).

  - HID: fix error message in hid_open_report()
    (bsc#1051510).

  - HID: hidraw: Fix invalid read in hidraw_ioctl
    (bsc#1051510).

  - HID: logitech: Fix general protection fault caused by
    Logitech driver (bsc#1051510).

  - HID: logitech-hidpp: do all FF cleanup in
    hidpp_ff_destroy() (bsc#1051510).

  - HID: prodikeys: Fix general protection fault during
    probe (bsc#1051510).

  - HID: sony: Fix memory corruption issue on cleanup
    (bsc#1051510).

  - hso: fix NULL-deref on tty open (bsc#1051510).

  - hwmon: (acpi_power_meter) Change log level for 'unsafe
    software power cap' (bsc#1051510).

  - hwrng: core - do not wait on add_early_randomness()
    (git-fixes).

  - i2c: riic: Clear NACK in tend isr (bsc#1051510).

  - IB/core, ipoib: Do not overreact to SM LID change event
    (bsc#1154108)

  - IB/hfi1: Remove overly conservative VM_EXEC flag check
    (bsc#1144449).

  - IB/mlx5: Consolidate use_umr checks into single function
    (bsc#1093205).

  - IB/mlx5: Fix MR re-registration flow to use UMR properly
    (bsc#1093205).

  - IB/mlx5: Report correctly tag matching rendezvous
    capability (bsc#1046305).

  - ieee802154: atusb: fix use-after-free at disconnect
    (bsc#1051510).

  - ieee802154: ca8210: prevent memory leak (bsc#1051510).

  - ieee802154: enforce CAP_NET_RAW for raw sockets
    (bsc#1051510).

  - iio: adc: ad799x: fix probe error handling
    (bsc#1051510).

  - iio: light: opt3001: fix mutex unlock race
    (bsc#1051510).

  - ima: always return negative code for error
    (bsc#1051510).

  - Input: da9063 - fix capability and drop KEY_SLEEP
    (bsc#1051510).

  - Input: synaptics-rmi4 - avoid processing unknown IRQs
    (bsc#1051510).

  - iommu/amd: Apply the same IVRS IOAPIC workaround to Acer
    Aspire A315-41 (bsc#1137799).

  - iommu/amd: Check PM_LEVEL_SIZE() condition in locked
    section (bsc#1154608).

  - iommu/amd: Override wrong IVRS IOAPIC on Raven Ridge
    systems (bsc#1137799).

  - iommu/amd: Remove domain->updated (bsc#1154610).

  - iommu/amd: Wait for completion of IOTLB flush in
    attach_device (bsc#1154611).

  - ipmi_si: Only schedule continuously in the thread in
    maintenance mode (bsc#1051510).

  - ipv6: drop incoming packets having a v4mapped source
    address (networking-stable-19_10_05).

  - ipv6: Fix the link time qualifier of
    'ping_v6_proc_exit_net()' (networking-stable-19_09_15).

  - ipv6: Handle missing host route in __ipv6_ifa_notify
    (networking-stable-19_10_05).

  - iwlwifi: pcie: fix memory leaks in
    iwl_pcie_ctxt_info_gen3_init (bsc#1111666).

  - ixgbe: Fix secpath usage for IPsec TX offload
    (bsc#1113994 bsc#1151807).

  - ixgbe: Prevent u8 wrapping of ITR value to something
    less than 10us (bsc#1101674).

  - ixgbe: sync the first fragment unconditionally
    (bsc#1133140).

  - kabi: net: sched: act_sample: fix psample group handling
    on overwrite (networking-stable-19_09_05).

  - kABI workaround for crypto/af_alg changes (bsc#1154737).

  - kABI workaround for drm_connector.registered type
    changes (bsc#1111666).

  - kABI workaround for snd_hda_pick_pin_fixup() changes
    (bsc#1051510).

  - kernel-binary.spec.in: Fix build of non-modular kernels
    (boo#1154578).

  - kernel-subpackage-build: create zero size ghost for
    uncompressed vmlinux (bsc#1154354).

  - kernel/sysctl.c: do not override max_threads provided by
    userspace (bnc#1150875).

  - ksm: cleanup stable_node chain collapse case
    (bnc#1144338).

  - ksm: fix use after free with merge_across_nodes = 0
    (bnc#1144338).

  - ksm: introduce ksm_max_page_sharing per page
    deduplication limit (bnc#1144338).

  - ksm: optimize refile of stable_node_dup at the head of
    the chain (bnc#1144338).

  - ksm: swap the two output parameters of chain/chain_prune
    (bnc#1144338).

  - kvm: Convert kvm_lock to a mutex (bsc#1117665).

  - kvm: MMU: drop vcpu param in gpte_access (bsc#1117665).

  - kvm: PPC: Book3S HV: use smp_mb() when setting/clearing
    host_ipi flag (bsc#1061840).

  - kvm: x86: add tracepoints around __direct_map and
    FNAME(fetch) (bsc#1117665).

  - kvm: x86: adjust kvm_mmu_page member to save 8 bytes
    (bsc#1117665).

  - kvm: x86: change kvm_mmu_page_get_gfn BUG_ON to WARN_ON
    (bsc#1117665).

  - kvm: x86: Do not release the page inside mmu_set_spte()
    (bsc#1117665).

  - kvm: x86: make FNAME(fetch) and __direct_map more
    similar (bsc#1117665).

  - kvm: x86, powerpc: do not allow clearing largepages
    debugfs entry (bsc#1117665).

  - kvm: x86: remove now unneeded hugepage gfn adjustment
    (bsc#1117665).

  - libertas: Add missing sentinel at end of if_usb.c
    fw_table (bsc#1051510).

  - lib/mpi: Fix karactx leak in mpi_powm (bsc#1051510).

  - libnvdimm/security: provide fix for secure-erase to use
    zero-key (bsc#1149853).

  - lpfc: Add additional discovery log messages
    (bsc#1154521).

  - lpfc: Add FA-WWN Async Event reporting (bsc#1154521).

  - lpfc: Add FC-AL support to lpe32000 models
    (bsc#1154521).

  - lpfc: Add log macros to allow print by serverity or
    verbocity setting (bsc#1154521).

  - lpfc: Fix bad ndlp ptr in xri aborted handling
    (bsc#1154521).

  - lpfc: fix coverity error of dereference after null check
    (bsc#1154521).

  - lpfc: Fix hardlockup in lpfc_abort_handler
    (bsc#1154521).

  - lpfc: Fix lockdep errors in sli_ringtx_put
    (bsc#1154521).

  - lpfc: fix lpfc_nvmet_mrq to be bound by hdw queue count
    (bsc#1154521).

  - lpfc: Fix reporting of read-only fw error errors
    (bsc#1154521).

  - lpfc: Fix SLI3 hba in loop mode not discovering devices
    (bsc#1154521).

  - lpfc: Make FW logging dynamically configurable
    (bsc#1154521).

  - lpfc: Remove lock contention target write path
    (bsc#1154521).

  - lpfc: Revise interrupt coalescing for missing scenarios
    (bsc#1154521).

  - lpfc: Slight fast-path Performance optimizations
    (bsc#1154521).

  - lpfc: Update lpfc version to 12.6.0.0 (bsc#1154521).

  - mac80211: accept deauth frames in IBSS mode
    (bsc#1051510).

  - mac80211: fix txq NULL pointer dereference
    (bsc#1051510).

  - mac80211: Reject malformed SSID elements (bsc#1051510).

  - macsec: drop skb sk before calling gro_cells_receive
    (bsc#1051510).

  - media: atmel: atmel-isc: fix asd memory allocation
    (bsc#1135642).

  - media: cpia2_usb: fix memory leaks (bsc#1051510).

  - media: dvb-core: fix a memory leak bug (bsc#1051510).

  - media: exynos4-is: fix leaked of_node references
    (bsc#1051510).

  - media: gspca: zero usb_buf on error (bsc#1051510).

  - media: hdpvr: Add device num check and handling
    (bsc#1051510).

  - media: hdpvr: add terminating 0 at end of string
    (bsc#1051510).

  - media: i2c: ov5645: Fix power sequence (bsc#1051510).

  - media: iguanair: add sanity checks (bsc#1051510).

  - media: omap3isp: Do not set streaming state on random
    subdevs (bsc#1051510).

  - media: omap3isp: Set device on omap3isp subdevs
    (bsc#1051510).

  - media: ov9650: add a sanity check (bsc#1051510).

  - media: radio/si470x: kill urb on error (bsc#1051510).

  - media: saa7134: fix terminology around
    saa7134_i2c_eeprom_md7134_gate() (bsc#1051510).

  - media: saa7146: add cleanup in hexium_attach()
    (bsc#1051510).

  - media: sn9c20x: Add MSI MS-1039 laptop to flip_dmi_table
    (bsc#1051510).

  - media: stkwebcam: fix runtime PM after driver unbind
    (bsc#1051510).

  - media: ttusb-dec: Fix info-leak in
    ttusb_dec_send_command() (bsc#1051510).

  - memstick: jmb38x_ms: Fix an error handling path in
    'jmb38x_ms_probe()' (bsc#1051510).

  - mfd: intel-lpss: Remove D3cold delay (bsc#1051510).

  - mISDN: enforce CAP_NET_RAW for raw sockets
    (bsc#1051510).

  - mld: fix memory leak in mld_del_delrec()
    (networking-stable-19_09_05).

  - mmc: sdhci: Fix incorrect switch to HS mode
    (bsc#1051510).

  - mmc: sdhci: improve ADMA error reporting (bsc#1051510).

  - mmc: sdhci-of-esdhc: set DMA snooping based on DMA
    coherence (bsc#1051510).

  - netfilter: nf_nat: do not bug when mapping already
    exists (bsc#1146612).

  - net: Fix null de-reference of device refcount
    (networking-stable-19_09_15).

  - net: fix skb use after free in netpoll
    (networking-stable-19_09_05).

  - net: gso: Fix skb_segment splat when splitting gso_size
    mangled skb having linear-headed frag_list
    (networking-stable-19_09_15).

  - net/ibmvnic: Fix EOI when running in XIVE mode
    (bsc#1089644, ltc#166495, ltc#165544, git-fixes).

  - net/mlx4_en: fix a memory leak bug (bsc#1046299).

  - net/mlx5: Add device ID of upcoming BlueField-2
    (bsc#1046303 ).

  - net/mlx5: Fix error handling in mlx5_load() (bsc#1046305
    ).

  - net/phy: fix DP83865 10 Mbps HDX loopback disable
    function (networking-stable-19_09_30).

  - net: qlogic: Fix memory leak in ql_alloc_large_buffers
    (networking-stable-19_10_05).

  - net: qrtr: Stop rx_worker before freeing node
    (networking-stable-19_09_30).

  - net/rds: Fix error handling in rds_ib_add_one()
    (networking-stable-19_10_05).

  - net/rds: fix warn in rds_message_alloc_sgs
    (bsc#1154848).

  - net/rds: remove user triggered WARN_ON in rds_sendmsg
    (bsc#1154848).

  - net: Replace NF_CT_ASSERT() with WARN_ON()
    (bsc#1146612).

  - net/sched: act_sample: do not push mac header on ip6gre
    ingress (networking-stable-19_09_30).

  - net: sched: act_sample: fix psample group handling on
    overwrite (networking-stable-19_09_05).

  - net_sched: add policy validation for action attributes
    (networking-stable-19_09_30).

  - net_sched: fix backward compatibility for TCA_ACT_KIND
    (git-fixes).

  - net: stmmac: dwmac-rk: Do not fail if phy regulator is
    absent (networking-stable-19_09_05).

  - net: Unpublish sk from sk_reuseport_cb before call_rcu
    (networking-stable-19_10_05).

  - nfc: fix attrs checks in netlink interface
    (bsc#1051510).

  - nfc: fix memory leak in llcp_sock_bind() (bsc#1051510).

  - nfc: pn533: fix use-after-free and memleaks
    (bsc#1051510).

  - NFSv4.1 - backchannel request should hold ref on xprt
    (bsc#1152624).

  - nl80211: fix NULL pointer dereference (bsc#1051510).

  - objtool: Clobber user CFLAGS variable (bsc#1153236).

  - openvswitch: change type of UPCALL_PID attribute to
    NLA_UNSPEC (networking-stable-19_09_30).

  - packaging: add support for riscv64

  - PCI: Correct pci=resource_alignment parameter example
    (bsc#1051510).

  - PCI: dra7xx: Fix legacy INTD IRQ handling (bsc#1087092).

  - PCI: hv: Use bytes 4 and 5 from instance ID as the PCI
    domain numbers (bsc#1153263).

  - PCI: PM: Fix pci_power_up() (bsc#1051510).

  - pinctrl: cherryview: restore Strago DMI workaround for
    all versions (bsc#1111666).

  - pinctrl: tegra: Fix write barrier placement in
    pmx_writel (bsc#1051510).

  - platform/x86: classmate-laptop: remove unused variable
    (bsc#1051510).

  - platform/x86: i2c-multi-instantiate: Derive the device
    name from parent (bsc#1111666).

  - platform/x86: i2c-multi-instantiate: Fail the probe if
    no IRQ provided (bsc#1111666).

  - platform/x86: pmc_atom: Add Siemens SIMATIC IPC277E to
    critclk_systems DMI table (bsc#1051510).

  - powerpc/64s/pseries: radix flush translations before MMU
    is enabled at boot (bsc#1055186).

  - powerpc/64s/radix: keep kernel ERAT over local
    process/guest invalidates (bsc#1055186).

  - powerpc/64s/radix: tidy up TLB flushing code
    (bsc#1055186).

  - powerpc/64s: Rename PPC_INVALIDATE_ERAT to
    PPC_ISA_3_0_INVALIDATE_ERAT (bsc#1055186).

  - powerpc/mm/book3s64: Move book3s64 code to
    pgtable-book3s64 (bsc#1055186).

  - powerpc/mm: mark more tlb functions as __always_inline
    (bsc#1055186).

  - powerpc/mm: Properly invalidate when setting process
    table base (bsc#1055186).

  - powerpc/mm/radix: mark as __tlbie_pid() and friends
    as__always_inline (bsc#1055186).

  - powerpc/mm/radix: mark __radix__flush_tlb_range_psize()
    as __always_inline (bsc#1055186).

  - powerpc/pseries/mobility: use cond_resched when updating
    device tree (bsc#1153112 ltc#181778).

  - powerpc/pseries: Remove confusing warning message
    (bsc#1109158).

  - powerpc/rtas: allow rescheduling while changing cpu
    states (bsc#1153112 ltc#181778).

  - powerplay: Respect units on max dcfclk watermark
    (bsc#1111666).

  - power: supply: sysfs: ratelimit property read error
    message (bsc#1051510).

  - qed: iWARP - Fix default window size to be based on chip
    (bsc#1050536 bsc#1050545).

  - qed: iWARP - Fix tc for MPA ll2 connection (bsc#1050536
    bsc#1050545).

  - qed: iWARP - fix uninitialized callback (bsc#1050536
    bsc#1050545).

  - qed: iWARP - Use READ_ONCE and smp_store_release to
    access ep->state (bsc#1050536 bsc#1050545).

  - qmi_wwan: add support for Cinterion CLS8 devices
    (networking-stable-19_10_05).

  - r8152: Set macpassthru in reset_resume callback
    (bsc#1051510).

  - RDMA/bnxt_re: Fix spelling mistake 'missin_resp' ->
    'missing_resp' (bsc#1050244).

  - RDMA: Fix goto target to release the allocated memory
    (bsc#1050244).

  - rds: Fix warning (bsc#1154848).

  - Revert 'drm/amd/display: Fix underscan not using proper
    scaling' (bsc#1111666).

  - Revert 'drm/amd/powerplay: Enable/Disable NBPSTATE on
    On/OFF of UVD' (bsc#1111666).

  - Revert 'drm/radeon: Fix EEH during kexec' (bsc#1051510).

  - rtlwifi: rtl8192cu: Fix value set in descriptor
    (bsc#1142635).

  - s390/cmf: set_schib_wait add timeout (bsc#1153509,
    bsc#1153476).

  - s390/crypto: fix gcm-aes-s390 selftest failures
    (bsc#1137861 LTC#178091).

  - sch_cbq: validate TCA_CBQ_WRROPT to avoid crash
    (networking-stable-19_10_05).

  - sch_dsmark: fix potential NULL deref in dsmark_init()
    (networking-stable-19_10_05).

  - sch_hhf: ensure quantum and hhf_non_hh_weight are
    non-zero (networking-stable-19_09_15).

  - sch_netem: fix a divide by zero in tabledist()
    (networking-stable-19_09_30).

  - scsi: lpfc: Check queue pointer before use
    (bsc#1154242).

  - scsi: lpfc: cleanup: remove unused fcp_txcmlpq_cnt
    (bsc#1154521).

  - scsi: lpfc: Complete removal of FCoE T10 PI support on
    SLI-4 adapters (bsc#1154521).

  - scsi: lpfc: Convert existing %pf users to %ps
    (bsc#1154521).

  - scsi: lpfc: Fix coverity errors on NULL pointer checks
    (bsc#1154521).

  - scsi: lpfc: Fix device recovery errors after PLOGI
    failures (bsc#1154521).

  - scsi: lpfc: Fix devices that do not return after devloss
    followed by rediscovery (bsc#1137040).

  - scsi: lpfc: Fix discovery failures when target device
    connectivity bounces (bsc#1154521).

  - scsi: lpfc: Fix GPF on scsi command completion
    (bsc#1154521).

  - scsi: lpfc: Fix hdwq sgl locks and irq handling
    (bsc#1154521).

  - scsi: lpfc: Fix host hang at boot or slow boot
    (bsc#1154521).

  - scsi: lpfc: Fix list corruption detected in
    lpfc_put_sgl_per_hdwq (bsc#1154521).

  - scsi: lpfc: Fix list corruption in lpfc_sli_get_iocbq
    (bsc#1154521).

  - scsi: lpfc: Fix locking on mailbox command completion
    (bsc#1154521).

  - scsi: lpfc: Fix miss of register read failure check
    (bsc#1154521).

  - scsi: lpfc: Fix null ptr oops updating lpfc_devloss_tmo
    via sysfs attribute (bsc#1140845).

  - scsi: lpfc: Fix NVMe ABTS in response to receiving an
    ABTS (bsc#1154521).

  - scsi: lpfc: Fix NVME io abort failures causing hangs
    (bsc#1154521).

  - scsi: lpfc: Fix premature re-enabling of interrupts in
    lpfc_sli_host_down (bsc#1154521).

  - scsi: lpfc: Fix propagation of devloss_tmo setting to
    nvme transport (bsc#1140883).

  - scsi: lpfc: Fix pt2pt discovery on SLI3 HBAs
    (bsc#1154521).

  - scsi: lpfc: Fix rpi release when deleting vport
    (bsc#1154521).

  - scsi: lpfc: Fix spinlock_irq issues in
    lpfc_els_flush_cmd() (bsc#1154521).

  - scsi: lpfc: Make function lpfc_defer_pt2pt_acc static
    (bsc#1154521).

  - scsi: lpfc: Remove bg debugfs buffers (bsc#1144375).

  - scsi: lpfc: remove left-over BUILD_NVME defines
    (bsc#1154268).

  - scsi: lpfc: Update async event logging (bsc#1154521).

  - scsi: lpfc: Update lpfc version to 12.4.0.1
    (bsc#1154521).

  - scsi: qedf: fc_rport_priv reference counting fixes
    (bsc#1098291).

  - scsi: qedf: Modify abort and tmf handler to handle edge
    condition and flush (bsc#1098291).

  - scsi: qla2xxx: Add error handling for PLOGI ELS
    passthrough (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Capture FW dump on MPI heartbeat stop
    event (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Check for MB timeout while capturing
    ISP27/28xx FW dump (bsc#1143706 bsc#1082635
    bsc#1123034).

  - scsi: qla2xxx: Dual FCP-NVMe target port support
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix N2N link reset (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix N2N link up fail (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix stale mem access on driver unload
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix unbound sleep in fcport delete path
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Fix wait condition in loop (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Improve logging for scan thread
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Optimize NPIV tear down process
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: remove redundant assignment to pointer
    host (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Remove WARN_ON_ONCE in
    qla2x00_status_cont_entry() (bsc#1143706 bsc#1082635
    bsc#1123034).

  - scsi: qla2xxx: Set remove flag for all VP (bsc#1143706
    bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Silence fwdump template message
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: qla2xxx: Update driver version to 10.01.00.20-k
    (bsc#1143706 bsc#1082635 bsc#1123034).

  - scsi: storvsc: setup 1:1 mapping between hardware queue
    and CPU queue (bsc#1140729).

  - sctp: Fix the link time qualifier of
    'sctp_ctrlsock_exit()' (networking-stable-19_09_15).

  - sctp: use transport pf_retrans in
    sctp_do_8_2_transport_strike
    (networking-stable-19_09_15).

  - Sign non-x86 kernels when possible (boo#1134303)

  - skge: fix checksum byte order
    (networking-stable-19_09_30).

  - sock_diag: fix autoloading of the raw_diag module
    (bsc#1152791).

  - sock_diag: request _diag module only when the family or
    proto has been registered (bsc#1152791).

  - staging: bcm2835-audio: Fix draining behavior regression
    (bsc#1111666).

  - staging: vt6655: Fix memory leak in vt6655_probe
    (bsc#1051510).

  - staging: wlan-ng: fix exit return when sme->key_idx >=
    NUM_WEPKEYS (bsc#1051510).

  - tcp: Do not dequeue SYN/FIN-segments from write-queue
    (git-gixes).

  - tcp: fix tcp_ecn_withdraw_cwr() to clear
    TCP_ECN_QUEUE_CWR (networking-stable-19_09_15).

  - tcp: inherit timestamp on mtu probe
    (networking-stable-19_09_05).

  - tcp: remove empty skb from write queue in error cases
    (networking-stable-19_09_05).

  - thermal: Fix use-after-free when unregistering thermal
    zone device (bsc#1051510).

  - thermal_hwmon: Sanitize thermal_zone type (bsc#1051510).

  - tipc: add NULL pointer check before calling kfree_rcu
    (networking-stable-19_09_15).

  - tipc: fix unlimited bundling of small messages
    (networking-stable-19_10_05).

  - tracing: Initialize iter->seq after zeroing in
    tracing_read_pipe() (bsc#1151508).

  - tun: fix use-after-free when register netdev failed
    (networking-stable-19_09_15).

  - tuntap: correctly set SOCKWQ_ASYNC_NOSPACE
    (bsc#1145099).

  - Update
    patches.suse/NFSv4-Check-the-return-value-of-update_open
    _stateid.patch (boo#1154189 bsc#1154747).

  - usb: adutux: fix NULL-derefs on disconnect
    (bsc#1142635).

  - usb: adutux: fix use-after-free on disconnect
    (bsc#1142635).

  - usb: adutux: fix use-after-free on release
    (bsc#1051510).

  - usb: chaoskey: fix use-after-free on release
    (bsc#1051510).

  - usb: dummy-hcd: fix power budget for SuperSpeed mode
    (bsc#1051510).

  - usb: iowarrior: fix use-after-free after driver unbind
    (bsc#1051510).

  - usb: iowarrior: fix use-after-free on disconnect
    (bsc#1051510).

  - usb: iowarrior: fix use-after-free on release
    (bsc#1051510).

  - usb: ldusb: fix memleak on disconnect (bsc#1051510).

  - usb: ldusb: fix NULL-derefs on driver unbind
    (bsc#1051510).

  - usb: ldusb: fix read info leaks (bsc#1051510).

  - usb: legousbtower: fix a signedness bug in tower_probe()
    (bsc#1051510).

  - usb: legousbtower: fix deadlock on disconnect
    (bsc#1142635).

  - usb: legousbtower: fix memleak on disconnect
    (bsc#1051510).

  - usb: legousbtower: fix open after failed reset request
    (bsc#1142635).

  - usb: legousbtower: fix potential NULL-deref on
    disconnect (bsc#1142635).

  - usb: legousbtower: fix slab info leak at probe
    (bsc#1142635).

  - usb: legousbtower: fix use-after-free on release
    (bsc#1051510).

  - usb: microtek: fix info-leak at probe (bsc#1142635).

  - usbnet: ignore endpoints with invalid wMaxPacketSize
    (bsc#1051510).

  - usbnet: sanity checking of packet sizes and device mtu
    (bsc#1051510).

  - usb: serial: fix runtime PM after driver unbind
    (bsc#1051510).

  - usb: serial: ftdi_sio: add device IDs for Sienna and
    Echelon PL-20 (bsc#1051510).

  - usb: serial: keyspan: fix NULL-derefs on open() and
    write() (bsc#1051510).

  - usb: serial: option: add support for Cinterion CLS8
    devices (bsc#1051510).

  - usb: serial: option: add Telit FN980 compositions
    (bsc#1051510).

  - usb: serial: ti_usb_3410_5052: fix port-close races
    (bsc#1051510).

  - usb: udc: lpc32xx: fix bad bit shift operation
    (bsc#1051510).

  - usb: usblcd: fix I/O after disconnect (bsc#1142635).

  - usb: usblp: fix runtime PM after driver unbind
    (bsc#1051510).

  - usb: usblp: fix use-after-free on disconnect
    (bsc#1051510).

  - usb: usb-skeleton: fix NULL-deref on disconnect
    (bsc#1051510).

  - usb: usb-skeleton: fix runtime PM after driver unbind
    (bsc#1051510).

  - usb: usb-skeleton: fix use-after-free after driver
    unbind (bsc#1051510).

  - usb: xhci: wait for CNR controller not ready bit in xhci
    resume (bsc#1051510).

  - usb: yurex: Do not retry on unexpected errors
    (bsc#1051510).

  - usb: yurex: fix NULL-derefs on disconnect (bsc#1051510).

  - vfio_pci: Restore original state on release
    (bsc#1051510).

  - vhost_net: conditionally enable tx polling
    (bsc#1145099).

  - video: of: display_timing: Add of_node_put() in
    of_get_display_timing() (bsc#1051510).

  - vsock: Fix a lockdep warning in __vsock_release()
    (networking-stable-19_10_05).

  - watchdog: imx2_wdt: fix min() calculation in
    imx2_wdt_set_timeout (bsc#1051510).

  - x86/asm: Fix MWAITX C-state hint value (bsc#1114279).

  - x86/boot/64: Make level2_kernel_pgt pages invalid
    outside kernel area (bnc#1153969).

  - x86/boot/64: Round memory hole size up to next PMD page
    (bnc#1153969).

  - x86/mm: Use WRITE_ONCE() when setting PTEs
    (bsc#1114279).

  - xen/netback: fix error path of xenvif_connect_data()
    (bsc#1065600).

  - xen/pv: Fix Xen PV guest int3 handling (bsc#1153811).

  - xhci: Check all endpoints for LPM timeout (bsc#1051510).

  - xhci: Fix false warning message about wrong bounce
    buffer write length (bsc#1051510).

  - xhci: Increase STS_SAVE timeout in xhci_suspend()
    (bsc#1051510).

  - xhci: Prevent device initiated U1/U2 link pm if exit
    latency is too long (bsc#1051510)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046299"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109158"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155186"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.25.1") ) flag++;

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
