#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-974.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123397);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-18281");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-974)");
  script_summary(english:"Check for the openSUSE-2019-974 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.0 kernel was updated to 4.12.14-lp150.12.28.1 to
receive various security and bugfixes.

The following security bugs were fixed :

  - CVE-2018-18281: The mremap() syscall performs TLB
    flushes after dropping pagetable locks. If a syscall
    such as ftruncate() removes entries from the pagetables
    of a task that is in the middle of mremap(), a stale TLB
    entry can remain for a short time that permits access to
    a physical page after it has been released back to the
    page allocator and reused. (bnc#1113769).

The following non-security bugs were fixed :

  - ACPI / LPSS: Add alternative ACPI HIDs for Cherry Trail
    DMA controllers (bsc#1051510).

  - ACPI / platform: Add SMB0001 HID to forbidden_id_list
    (bsc#1051510).

  - ACPI / watchdog: Prefer iTCO_wdt always when WDAT table
    uses RTC SRAM (bsc#1051510).

  - ACPI/APEI: Handle GSIV and GPIO notification types
    (bsc#1115567). 

  - ACPI/IORT: Fix iort_get_platform_device_domain()
    uninitialized pointer value (bsc#1051510).

  - ACPICA: Tables: Add WSMT support (bsc#1089350).

  - ALSA: ac97: Fix incorrect bit shift at AC97-SPSA control
    write (bsc#1051510).

  - ALSA: ca0106: Disable IZD on SB0570 DAC to fix audio
    pops (bsc#1051510).

  - ALSA: control: Fix race between adding and removing a
    user element (bsc#1051510).

  - ALSA: hda/ca0132 - Call pci_iounmap() instead of
    iounmap() (bsc#1051510).

  - ALSA: hda/realtek - Add GPIO data update helper
    (bsc#1051510).

  - ALSA: hda/realtek - Add auto-mute quirk for HP Spectre
    x360 laptop (bsc#1051510).

  - ALSA: hda/realtek - Allow skipping spec->init_amp
    detection (bsc#1051510).

  - ALSA: hda/realtek - Fix HP Headset Mic can't record
    (bsc#1051510).

  - ALSA: hda/realtek - Manage GPIO bits commonly
    (bsc#1051510).

  - ALSA: hda/realtek - Simplify Dell XPS13 GPIO handling
    (bsc#1051510).

  - ALSA: hda/realtek - Support ALC300 (bsc#1051510).

  - ALSA: hda/realtek - fix headset mic detection for MSI
    MS-B171 (bsc#1051510).

  - ALSA: hda/realtek - fix the pop noise on headphone for
    lenovo laptops (bsc#1051510).

  - ALSA: hda: Add ASRock N68C-S UCC the power_save
    blacklist (bsc#1051510).

  - ALSA: oss: Use kvzalloc() for local buffer allocations
    (bsc#1051510).

  - ALSA: sparc: Fix invalid snd_free_pages() at error path
    (bsc#1051510).

  - ALSA: usb-audio: Add vendor and product name for Dell
    WD19 Dock (bsc#1051510).

  - ALSA: wss: Fix invalid snd_free_pages() at error path
    (bsc#1051510).

  - ARM: dts: at91: add new compatibility string for macb on
    sama5d3 (bsc#1051510).

  - ASoC: Intel: cht_bsw_max98090: add support for Baytrail
    (bsc#1051510).

  - ASoC: dwc: Added a quirk DW_I2S_QUIRK_16BIT_IDX_OVERRIDE
    to dwc (bsc#1085535)

  - ASoC: intel: cht_bsw_max98090_ti: Add quirk for boards
    using pmc_plt_clk_0 (bsc#1051510).

  - ASoC: sun8i-codec: fix crash on module removal
    (bsc#1051510).

  - Bluetooth: SMP: fix crash in unpairing (bsc#1051510).

  - Bluetooth: btbcm: Add entry for BCM4335C0 UART bluetooth
    (bsc#1051510).

  - Btrfs: fix assertion failure during fsync in no-holes
    mode (bsc#1118136).

  - Btrfs: fix assertion on fsync of regular file when using
    no-holes feature (bsc#1118137).

  - Btrfs: fix cur_offset in the error case for nocow
    (bsc#1118140).

  - Btrfs: fix data corruption due to cloning of eof block
    (bsc#1116878).

  - Btrfs: fix deadlock on tree root leaf when finding free
    extent (bsc#1116876).

  - Btrfs: fix deadlock when writing out free space caches
    (bsc#1116700).

  - Btrfs: fix infinite loop on inode eviction after
    deduplication of eof block (bsc#1116877).

  - Btrfs: fix NULL pointer dereference on compressed write
    path error (bsc#1116698).

  - Btrfs: fix use-after-free during inode eviction
    (bsc#1116701).

  - Btrfs: fix use-after-free when dumping free space
    (bsc#1116862).

  - Btrfs: fix warning when replaying log after fsync of a
    tmpfile (bsc#1116692).

  - Btrfs: fix wrong dentries after fsync of file that got
    its parent replaced (bsc#1116693).

  - Btrfs: send, fix infinite loop due to directory rename
    dependencies (bsc#1118138).

  - Documentation/l1tf: Fix typos (bsc#1051510).

  - Documentation/l1tf: Remove Yonah processors from not
    vulnerable list (bsc#1051510).

  - EDAC, thunderx: Fix memory leak in
    thunderx_l2c_threaded_isr() (bsc#1114279).

  - EDAC: Raise the maximum number of memory controllers
    (bsc#1113780).

  - Fix kABI for 'Ensure we commit after writeback is
    complete' (bsc#1111809).

  - Fix some patch headers which diverge from RFC5322
    Manually fix some patches which have an invalid header.

  - HID: hiddev: fix potential Spectre v1 (bsc#1051510).

  - HID: uhid: forbid UHID_CREATE under KERNEL_DS or
    elevated privileges (bsc#1051510).

  - Input: elan_i2c - add ACPI ID for Lenovo IdeaPad
    330-15IGM (bsc#1051510).

  - Input: synaptics - avoid using uninitialized variable
    when probing (bsc#1051510).

  - Input: xpad - add PDP device id 0x02a4 (bsc#1051510).

  - Input: xpad - add support for Xbox1 PDP Camo series
    gamepad (bsc#1051510).

  - Input: xpad - avoid using __set_bit() for capabilities
    (bsc#1051510).

  - Input: xpad - fix some coding style issues
    (bsc#1051510).

  - KABI fix for 'NFSv4.1: Fix up replays of interrupted
    requests' (git-fixes).

  - KABI: hide new member in struct iommu_table from
    genksyms (bsc#1061840).

  - KABI: powerpc: Revert npu callback signature change
    (bsc#1055120).

  - KABI: powerpc: export __find_linux_pte as
    __find_linux_pte_or_hugepte (bsc#1061840).

  - KVM: PPC: Add pt_regs into kvm_vcpu_arch and move
    vcpu->arch.gpr[] into it (bsc#1061840).

  - KVM: PPC: Avoid marking DMA-mapped pages dirty in real
    mode (bsc#1061840).

  - KVM: PPC: Book 3S HV: Do ptesync in radix guest exit
    path (bsc#1061840).

  - KVM: PPC: Book3S HV: Add 'online' register to ONE_REG
    interface (bsc#1061840).

  - KVM: PPC: Book3S HV: Add of_node_put() in success path
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Allow HPT and radix on the same
    core for POWER9 v2.2 (bsc#1061840).

  - KVM: PPC: Book3S HV: Allow creating max number of VCPUs
    on POWER9 (bsc#1061840).

  - KVM: PPC: Book3S HV: Avoid crash from THP collapse
    during radix page fault (bsc#1061840).

  - KVM: PPC: Book3S HV: Avoid shifts by negative amounts
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Check DR not IR to chose real vs
    virt mode MMIOs (bsc#1061840).

  - KVM: PPC: Book3S HV: Do SLB load/unload with guest LPCR
    value loaded (bsc#1061840).

  - KVM: PPC: Book3S HV: Do not truncate HPTE index in xlate
    function (bsc#1061840).

  - KVM: PPC: Book3S HV: Do not use compound_order to
    determine host mapping size (bsc#1061840).

  - KVM: PPC: Book3S HV: Do not use existing 'prodded' flag
    for XIVE escalations (bsc#1061840).

  - KVM: PPC: Book3S HV: Enable migration of decrementer
    register (bsc#1061840).

  - KVM: PPC: Book3S HV: Factor fake-suspend handling out of
    kvmppc_save/restore_tm (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix VRMA initialization with 2MB or
    1GB memory backing (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix conditions for starting vcpu
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix constant size warning
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix duplication of host SLB entries
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix guest r11 corruption with
    POWER9 TM workarounds (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix handling of large pages in
    radix page fault handler (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix handling of secondary HPTEG in
    HPT resizing code (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix inaccurate comment
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix kvmppc_bad_host_intr for real
    mode interrupts (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix trap number return from
    __kvmppc_vcore_entry (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix typo in
    kvmppc_hv_get_dirty_log_radix() (bsc#1061840).

  - KVM: PPC: Book3S HV: Handle 1GB pages in radix page
    fault handler (bsc#1061840).

  - KVM: PPC: Book3S HV: Improve handling of debug-trigger
    HMIs on POWER9 (bsc#1061840).

  - KVM: PPC: Book3S HV: Keep XIVE escalation interrupt
    masked unless ceded (bsc#1061840).

  - KVM: PPC: Book3S HV: Lockless tlbie for HPT hcalls
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Make HPT resizing work on POWER9
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Make radix clear pte when unmapping
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Make radix use correct tlbie
    sequence in kvmppc_radix_tlbie_page (bsc#1061840).

  - KVM: PPC: Book3S HV: Make xive_pushed a byte, not a word
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Pack VCORE IDs to access full VCPU
    ID space (bsc#1061840).

  - KVM: PPC: Book3S HV: Radix page fault handler
    optimizations (bsc#1061840).

  - KVM: PPC: Book3S HV: Read kvm->arch.emul_smt_mode under
    kvm->lock (bsc#1061840).

  - KVM: PPC: Book3S HV: Recursively unmap all page table
    entries when unmapping (bsc#1061840).

  - KVM: PPC: Book3S HV: Remove useless statement
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Remove vcpu->arch.dec usage
    (bsc#1061840).

  - KVM: PPC: Book3S HV: Send kvmppc_bad_interrupt NMIs to
    Linux handlers (bsc#1061840).

  - KVM: PPC: Book3S HV: Set RWMR on POWER8 so PURR/SPURR
    count correctly (bsc#1061840).

  - KVM: PPC: Book3S HV: Snapshot timebase offset on guest
    entry (bsc#1061840).

  - KVM: PPC: Book3S HV: Streamline setting of reference and
    change bits (bsc#1061840).

  - KVM: PPC: Book3S HV: Use __gfn_to_pfn_memslot() in page
    fault handler (bsc#1061840).

  - KVM: PPC: Book3S HV: Use a helper to unmap ptes in the
    radix fault path (bsc#1061840).

  - KVM: PPC: Book3S HV: XIVE: Resend re-routed interrupts
    on CPU priority change (bsc#1061840).

  - KVM: PPC: Book3S HV: radix: Do not clear partition PTE
    when RC or write bits do not match (bsc#1061840).

  - KVM: PPC: Book3S HV: radix: Refine IO region partition
    scope attributes (bsc#1061840).

  - KVM: PPC: Book3S PR: Add guest MSR parameter for
    kvmppc_save_tm()/kvmppc_restore_tm() (bsc#1061840).

  - KVM: PPC: Book3S PR: Move
    kvmppc_save_tm/kvmppc_restore_tm to separate file
    (bsc#1061840).

  - KVM: PPC: Book3S: Add MMIO emulation for VMX
    instructions (bsc#1061840).

  - KVM: PPC: Book3S: Allow backing bigger guest IOMMU pages
    with smaller physical pages (bsc#1061840).

  - KVM: PPC: Book3S: Check KVM_CREATE_SPAPR_TCE_64
    parameters (bsc#1061840).

  - KVM: PPC: Book3S: Eliminate some unnecessary checks
    (bsc#1061840).

  - KVM: PPC: Book3S: Fix compile error that occurs with
    some gcc versions (bsc#1061840).

  - KVM: PPC: Book3S: Fix matching of hardware and emulated
    TCE tables (bsc#1061840).

  - KVM: PPC: Book3S: Use correct page shift in H_STUFF_TCE
    (bsc#1061840).

  - KVM: PPC: Fix a mmio_host_swabbed uninitialized usage
    issue (bsc#1061840).

  - KVM: PPC: Make iommu_table::it_userspace big endian
    (bsc#1061840).

  - KVM: PPC: Move nip/ctr/lr/xer registers to pt_regs in
    kvm_vcpu_arch (bsc#1061840).

  - KVM: PPC: Use seq_puts() in kvmppc_exit_timing_show()
    (bsc#1061840).

  - KVM: VMX: re-add ple_gap module parameter (bsc#1106240).

  - KVM: arm/arm64: Introduce vcpu_el1_is_32bit
    (bsc#1110998).

  - KVM: nVMX: Always reflect #NM VM-exits to L1
    (bsc#1106240).

  - KVM: nVMX: move check_vmentry_postreqs() call to
    nested_vmx_enter_non_root_mode() (bsc#1106240).

  - KVM: s390: vsie: copy wrapping keys to right place
    (git-fixes).

  - KVM: x86: Fix kernel info-leak in KVM_HC_CLOCK_PAIRING
    hypercall (bsc#1106240).

  - MD: fix invalid stored role for a disk - try2
    (git-fixes).

  - NFS: Avoid RCU usage in tracepoints (git-fixes).

  - NFS: Ensure we commit after writeback is complete
    (bsc#1111809).

  - NFS: Fix a typo in nfs_rename() (git-fixes).

  - NFS: Fix an incorrect type in struct nfs_direct_req
    (git-fixes).

  - NFS: Fix typo in nomigration mount option (git-fixes).

  - NFS: Fix unstable write completion (git-fixes).

  - NFS: commit direct writes even if they fail partially
    (git-fixes).

  - NFSv4.0 fix client reference leak in callback
    (git-fixes).

  - NFSv4.1 fix infinite loop on I/O (git-fixes).

  - NFSv4.1: Fix a potential layoutget/layoutrecall deadlock
    (git-fixes).

  - NFSv4.1: Fix the client behaviour on
    NFS4ERR_SEQ_FALSE_RETRY (git-fixes).

  - NFSv4.1: Fix up replays of interrupted requests
    (git-fixes).

  - NFSv4: Fix a typo in nfs41_sequence_process (git-fixes).

  - PCI/ASPM: Do not initialize link state when
    aspm_disabled is set (bsc#1051510).

  - PCI/MSI: Warn and return error if driver enables
    MSI/MSI-X twice (bsc#1051510).

  - PCI: Add Device IDs for Intel GPU 'spurious interrupt'
    quirk (bsc#1051510).

  - PCI: hv: Use effective affinity mask (bsc#1109772).

  - PCI: imx6: Fix link training status detection in link up
    check (bsc#1109806).

  - PCI: iproc: Remove PAXC slot check to allow VF support
    (bsc#1109806).

  - PCI: vmd: Assign vector zero to all bridges
    (bsc#1109806).

  - PCI: vmd: Detach resources after stopping root bus
    (bsc#1109806).

  - PCI: vmd: White list for fast interrupt handlers
    (bsc#1109806).

  - SUNRPC: Allow connect to return EHOSTUNREACH
    (git-fixes).

  - SUNRPC: Fix tracepoint storage issues with svc_recv and
    svc_rqst_status (git-fixes).

  - USB: misc: appledisplay: add 20' Apple Cinema Display
    (bsc#1051510).

  - USB: omap_udc: fix rejection of out transfers when DMA
    is used (bsc#1051510).

  - USB: quirks: Add no-lpm quirk for Raydium touchscreens
    (bsc#1051510).

  - USB: serial: option: add two-endpoints device-id flag
    (bsc#1051510).

  - USB: serial: option: drop redundant interface-class test
    (bsc#1051510).

  - USB: serial: option: improve Quectel EP06 detection
    (bsc#1051510).

  - VFS: close race between getcwd() and d_move()
    (git-fixes).

  - VMCI: Resource wildcard match fixed (bsc#1051510).

  - acpi, nfit: Fix ARS overflow continuation (bsc#1116895).

  - acpi/nfit, x86/mce: Handle only uncorrectable machine
    checks (bsc#1114279).

  - acpi/nfit, x86/mce: Validate a MCE's address before
    using it (bsc#1114279).

  - act_ife: fix a potential use-after-free
    (networking-stable-18_09_11).

  - amd/iommu: Fix Guest Virtual APIC Log Tail Address
    Register (bsc#1106105).

  - arm64: KVM: Move CPU ID reg trap setup off the world
    switch path (bsc#1110998).

  - arm64: KVM: Sanitize PSTATE.M when being set from
    userspace (bsc#1110998).

  - arm64: KVM: Tighten guest core register access from
    userspace (bsc#1110998).

  - ata: Fix racy link clearance (bsc#1107866).

  - ataflop: fix error handling during setup (bsc#1051510).

  - ath10k: schedule hardware restart if WMI command times
    out (bsc#1051510).

  - autofs: fix autofs_sbi() does not check super block type
    (git-fixes).

  - autofs: fix slab out of bounds read in getname_kernel()
    (git-fixes).

  - autofs: mount point create should honour passed in mode
    (git-fixes).

  - badblocks: fix wrong return value in badblocks_set if
    badblocks are disabled (git-fixes).

  - batman-adv: Expand merged fragment buffer for full
    packet (bsc#1051510).

  - batman-adv: Use explicit tvlv padding for ELP packets
    (bsc#1051510).

  - bitops: protect variables in bit_clear_unless() macro
    (bsc#1051510).

  - bitops: protect variables in set_mask_bits() macro
    (bsc#1051510).

  - block: copy ioprio in __bio_clone_fast() (bsc#1082653).

  - block: respect virtual boundary mask in bvecs
    (bsc#1113412).

  - bnxt_en: Fix TX timeout during netpoll
    (networking-stable-18_10_16).

  - bnxt_en: free hwrm resources, if driver probe fails
    (networking-stable-18_10_16).

  - bonding: avoid possible dead-lock
    (networking-stable-18_10_16).

  - bonding: fix length of actor system
    (networking-stable-18_11_02).

  - bonding: fix warning message
    (networking-stable-18_10_16).

  - bonding: pass link-local packets to bonding master also
    (networking-stable-18_10_16).

  - bpf, net: add skb_mac_header_len helper
    (networking-stable-18_09_24).

  - bpf: fix partial copy of map_ptr when dst is scalar
    (bsc#1083647).

  - bpf: wait for running BPF programs when updating
    map-in-map (bsc#1083647).

  - brcmfmac: fix for proper support of 160MHz bandwidth
    (bsc#1051510).

  - brcmfmac: fix reporting support for 160 MHz channels
    (bsc#1051510).

  - brcmutil: really fix decoding channel info for 160 MHz
    bandwidth (bsc#1051510).

  - bridge: do not add port to router list when receives
    query with source 0.0.0.0 (networking-stable-18_11_02).

  - btrfs: make sure we create all new block groups
    (bsc#1116699).

  - btrfs: protect space cache inode alloc with GFP_NOFS
    (bsc#1116863).

  - cachefiles: fix the race between
    cachefiles_bury_object() and rmdir(2) (bsc#1051510).

  - can: dev: __can_get_echo_skb(): Do not crash the kernel
    if can_priv::echo_skb is accessed out of bounds
    (bsc#1051510).

  - can: dev: __can_get_echo_skb(): print error message, if
    trying to echo non existing skb (bsc#1051510).

  - can: dev: __can_get_echo_skb(): replace struct can_frame
    by canfd_frame to access frame length (bsc#1051510).

  - can: dev: can_get_echo_skb(): factor out non sending
    code to __can_get_echo_skb() (bsc#1051510).

  - can: hi311x: Use level-triggered interrupt
    (bsc#1051510).

  - can: raw: check for CAN FD capable netdev in
    raw_sendmsg() (bsc#1051510).

  - can: rcar_can: Fix erroneous registration (bsc#1051510).

  - can: rx-offload: introduce can_rx_offload_get_echo_skb()
    and can_rx_offload_queue_sorted() functions
    (bsc#1051510).

  - cdc-acm: correct counting of UART states in serial state
    notification (bsc#1051510).

  - cdc-acm: do not reset notification buffer index upon urb
    unlinking (bsc#1051510).

  - ceph: fix dentry leak in ceph_readdir_prepopulate
    (bsc#1114839).

  - ceph: quota: fix NULL pointer dereference in quota check
    (bsc#1114839).

  - cfg80211: Address some corner cases in scan result
    channel updating (bsc#1051510).

  - cfg80211: fix use-after-free in reg_process_hint()
    (bsc#1051510).

  - clk: at91: Fix division by zero in PLL recalc_rate()
    (bsc#1051510).

  - clk: fixed-factor: fix of_node_get-put imbalance
    (bsc#1051510).

  - clk: fixed-rate: fix of_node_get-put imbalance
    (bsc#1051510).

  - clk: mmp2: fix the clock id for sdh2_clk and sdh3_clk
    (bsc#1051510).

  - clk: rockchip: Fix static checker warning in
    rockchip_ddrclk_get_parent call (bsc#1051510).

  - clk: s2mps11: Add used attribute to s2mps11_dt_match
    (bsc#1051510).

  - clk: s2mps11: Fix matching when built as module and DT
    node contains compatible (bsc#1051510).

  - clk: samsung: exynos5420: Enable PERIS clocks for
    suspend (bsc#1051510).

  - clockevents/drivers/i8253: Add support for PIT shutdown
    quirk (bsc#1051510).

  - configfs: replace strncpy with memcpy (bsc#1051510).

  - crypto: simd - correctly take reqsize of wrapped
    skcipher into account (bsc#1051510).

  - do d_instantiate/unlock_new_inode combinations safely
    (git-fixes).

  - driver/dma/ioat: Call del_timer_sync() without holding
    prep_lock (bsc#1051510).

  - drm/amdgpu: add missing CHIP_HAINAN in
    amdgpu_ucode_get_load_type (bsc#1051510).

  - drm/ast: Fix incorrect free on ioregs (bsc#1051510).

  - drm/ast: Remove existing framebuffers before loading
    driver (boo#1112963)

  - drm/ast: change resolution may cause screen blurred
    (boo#1112963).

  - drm/ast: fixed cursor may disappear sometimes
    (bsc#1051510).

  - drm/dp_mst: Check if primary mstb is null (bsc#1051510).

  - drm/dp_mst: Skip validating ports during destruction,
    just ref (bsc#1051510).

  - drm/edid: Add 6 bpc quirk for BOE panel (bsc#1051510).

  - drm/edid: Add 6 bpc quirk for BOE panel in HP Pavilion
    15-n233sl (bsc#1113722)

  - drm/i915/execlists: Force write serialisation into
    context image vs execution (bsc#1051510).

  - drm/i915/glk: Remove 99% limitation (bsc#1051510).

  - drm/i915/hdmi: Add HDMI 2.0 audio clock recovery N
    values (bsc#1051510).

  - drm/i915: Do not oops during modeset shutdown after lpe
    audio deinit (bsc#1051510).

  - drm/i915: Do not unset intel_connector->mst_port
    (bsc#1051510).

  - drm/i915: Fix ilk+ watermarks when disabling pipes
    (bsc#1051510).

  - drm/i915: Large page offsets for pread/pwrite
    (bsc#1051510).

  - drm/i915: Mark pin flags as u64 (bsc#1051510).

  - drm/i915: Skip vcpi allocation for MSTB ports that are
    gone (bsc#1051510).

  - drm/i915: Write GPU relocs harder with gen3
    (bsc#1051510).

  - drm/meson: Enable fast_io in meson_dw_hdmi_regmap_config
    (bsc#1051510).

  - drm/meson: Fix OOB memory accesses in
    meson_viu_set_osd_lut() (bsc#1051510).

  - drm/meson: add support for 1080p25 mode (bsc#1051510).

  - drm/nouveau: Check backlight IDs are >= 0, not > 0
    (bsc#1051510).

  - drm/omap: fix memory barrier bug in DMM driver
    (bsc#1051510).

  - drm/rockchip: Allow driver to be shutdown on
    reboot/kexec (bsc#1051510).

  - drm: fb-helper: Reject all pixel format changing
    requests (bsc#1113722)

  - ext4: add missing brelse() add_new_gdb_meta_bg()'s error
    path (bsc#1117795).

  - ext4: add missing brelse() in
    set_flexbg_block_bitmap()'s error path (bsc#1117794).

  - ext4: add missing brelse() update_backups()'s error path
    (bsc#1117796).

  - ext4: avoid buffer leak in ext4_orphan_add() after prior
    errors (bsc#1117802).

  - ext4: avoid buffer leak on shutdown in
    ext4_mark_iloc_dirty() (bsc#1117801).

  - ext4: avoid potential extra brelse in
    setup_new_flex_group_blocks() (bsc#1117792).

  - ext4: fix buffer leak in __ext4_read_dirblock() on error
    path (bsc#1117807).

  - ext4: fix buffer leak in ext4_xattr_move_to_block() on
    error path (bsc#1117806).

  - ext4: fix missing cleanup if ext4_alloc_flex_bg_array()
    fails while resizing (bsc#1117798).

  - ext4: fix possible inode leak in the retry loop of
    ext4_resize_fs() (bsc#1117799).

  - ext4: fix possible leak of s_journal_flag_rwsem in error
    path (bsc#1117804).

  - ext4: fix possible leak of sbi->s_group_desc_leak in
    error path (bsc#1117803).

  - ext4: fix setattr project check in fssetxattr ioctl
    (bsc#1117789).

  - ext4: fix use-after-free race in ext4_remount()'s error
    path (bsc#1117791).

  - ext4: initialize retries variable in
    ext4_da_write_inline_data_begin() (bsc#1117788).

  - ext4: propagate error from dquot_initialize() in
    EXT4_IOC_FSSETXATTR (bsc#1117790).

  - ext4: release bs.bh before re-using in
    ext4_xattr_block_find() (bsc#1117805).

  - fbdev: fix broken menu dependencies (bsc#1113722)

  - firmware: dcdbas: Add support for WSMT ACPI table
    (bsc#1089350 ).

  - firmware: dcdbas: include linux/io.h (bsc#1089350).

  - floppy: fix race condition in __floppy_read_block_0()
    (bsc#1051510).

  - flow_dissector: do not dissect l4 ports for fragments
    (networking-stable-18_11_21).

  - fs/dcache.c: fix kmemcheck splat at
    take_dentry_name_snapshot() (git-fixes).

  - fs: Make extension of struct super_block transparent
    (bsc#1117822).

  - fs: dcache: Avoid livelock between d_alloc_parallel and
    __d_add (git-fixes).

  - fs: dcache: Use READ_ONCE when accessing i_dir_seq
    (git-fixes).

  - fscache: fix race between enablement and dropping of
    object (bsc#1107385).

  - fsnotify: Fix busy inodes during unmount (bsc#1117822).

  - fsnotify: fix ignore mask logic in fsnotify()
    (bsc#1115074).

  - ftrace: Fix debug preempt config name in
    stack_tracer_(en,dis)able (bsc#1117172).

  - ftrace: Fix kmemleak in unregister_ftrace_graph
    (bsc#1117181).

  - ftrace: Fix memleak when unregistering dynamic ops when
    tracing disabled (bsc#1117174).

  - ftrace: Remove incorrect setting of glob search field
    (bsc#1117184).

  - genirq: Fix race on spurious interrupt detection
    (bsc#1051510).

  - getname_kernel() needs to make sure that ->name !=
    ->iname in long case (git-fixes).

  - gpio: do not free unallocated ida on
    gpiochip_add_data_with_key() error path (bsc#1051510).

  - grace: replace BUG_ON by WARN_ONCE in exit_net hook
    (git-fixes).

  - gso_segment: Reset skb->mac_len after modifying network
    header (networking-stable-18_09_24).

  - hv_netvsc: ignore devices that are not PCI
    (networking-stable-18_09_11).

  - hwmon (ina2xx) Fix NULL id pointer in probe()
    (bsc#1051510).

  - hwmon: (core) Fix double-free in
    __hwmon_device_register() (bsc#1051510).

  - hwmon: (ibmpowernv) Remove bogus __init annotations
    (bsc#1051510).

  - hwmon: (ina2xx) Fix current value calculation
    (bsc#1051510).

  - hwmon: (nct6775) Fix potential Spectre v1 (bsc#1051510).

  - hwmon: (pmbus) Fix page count auto-detection
    (bsc#1051510).

  - hwmon: (pwm-fan) Set fan speed to 0 on suspend
    (bsc#1051510).

  - hwmon: (raspberrypi) Fix initial notify (bsc#1051510).

  - hwmon: (w83795) temp4_type has writable permission
    (bsc#1051510).

  - ibmvnic: fix accelerated VLAN handling ().

  - ibmvnic: fix index in release_rx_pools (bsc#1115440,
    bsc#1115433).

  - ibmvnic: remove ndo_poll_controller ().

  - iio: accel: adxl345: convert address field usage in
    iio_chan_spec (bsc#1051510).

  - iio: ad5064: Fix regulator handling (bsc#1051510).

  - iio:st_magn: Fix enable device after trigger
    (bsc#1051510).

  - ima: fix showing large 'violations' or
    'runtime_measurements_count' (bsc#1051510).

  - include/linux/pfn_t.h: force '~' to be parsed as an
    unary operator (bsc#1051510).

  - inet: make sure to grab rcu_read_lock before using
    ireq->ireq_opt (networking-stable-18_10_16).

  - iommu/arm-smmu: Ensure that page-table updates are
    visible before TLBI (bsc#1106237).

  - iommu/ipmmu-vmsa: Fix crash on early domain free
    (bsc#1106105).

  - iommu/vt-d: Fix NULL pointer dereference in
    prq_event_thread() (bsc#1106105).

  - iommu/vt-d: Use memunmap to free memremap (bsc#1106105).

  - ip6_tunnel: Fix encapsulation layout
    (networking-stable-18_11_02).

  - ip6_tunnel: be careful when accessing the inner header
    (networking-stable-18_10_16).

  - ip6_vti: fix a NULL pointer deference when destroy vti6
    tunnel (networking-stable-18_09_11).

  - ip_tunnel: be careful when accessing the inner header
    (networking-stable-18_10_16).

  - ip_tunnel: do not force DF when MTU is locked
    (networking-stable-18_11_21).

  - ipmi: Fix timer race with module unload (bsc#1051510).

  - ipv4: lock mtu in fnhe when received PMTU
    net.ipv4.route.min_pmtu (networking-stable-18_11_21).

  - ipv4: tcp: send zero IPID for RST and ACK sent in
    SYN-RECV and TIME-WAIT state
    (networking-stable-18_09_11).

  - ipv6/ndisc: Preserve IPv6 control buffer if protocol
    error handlers are called (networking-stable-18_11_02).

  - ipv6: fix possible use-after-free in ip6_xmit()
    (networking-stable-18_09_24).

  - ipv6: mcast: fix a use-after-free in inet6_mc_check
    (networking-stable-18_11_02).

  - ipv6: take rcu lock in rawv6_send_hdrinc()
    (networking-stable-18_10_16).

  - iwlwifi: dbg: allow wrt collection before ALIVE
    (bsc#1051510).

  - iwlwifi: do not WARN on trying to dump dead firmware
    (bsc#1051510).

  - iwlwifi: mvm: check for short GI only for OFDM
    (bsc#1051510).

  - iwlwifi: mvm: check return value of
    rs_rate_from_ucode_rate() (bsc#1051510).

  - iwlwifi: mvm: do not use SAR Geo if basic SAR is not
    used (bsc#1051510).

  - iwlwifi: mvm: fix BAR seq ctrl reporting (bsc#1051510).

  - iwlwifi: mvm: fix regulatory domain update when the
    firmware starts (bsc#1051510).

  - iwlwifi: mvm: support sta_statistics() even on older
    firmware (bsc#1051510).

  - iwlwifi: pcie: avoid empty free RB queue (bsc#1051510).

  - kABI: protect struct fib_nh_exception (kabi).

  - kABI: protect struct rtable (kabi).

  - kabi/severities: ignore __xive_vm_h_* KVM internal
    symbols.

  - kabi/severities: ignore ppc64 realmode helpers. KVM
    fixes remove exports of realmode_pfn_to_page
    iommu_tce_xchg_rm mm_iommu_lookup_rm
    mm_iommu_ua_to_hpa_rm. Some are no longer used and
    others are no longer exported because the code was
    consolideted in one place. These helpers are to be
    called in realmode and linking to them from non-KVM
    modules is a bug. Hence removing them does not break
    KABI.

  - kabi: mask raw in struct bpf_reg_state (bsc#1083647).

  - kbuild: fix kernel/bounds.c 'W=1' warning (bsc#1051510).

  - kbuild: move '_all' target out of $(KBUILD_SRC)
    conditional (bsc#1114279).

  - kgdboc: Passing ekgdboc to command line causes panic
    (bsc#1051510).

  - libceph: bump CEPH_MSG_MAX_DATA_LEN (bsc#1114839).

  - libertas: do not set URB_ZERO_PACKET on IN USB transfer
    (bsc#1051510).

  - libnvdimm, region: Fail badblocks listing for inactive
    regions (bsc#1116899).

  - libnvdimm: Hold reference on parent while scheduling
    async init (bsc#1116891).

  - livepatch: create and include UAPI headers ().

  - llc: set SOCK_RCU_FREE in llc_sap_add_socket()
    (networking-stable-18_11_02).

  - lockd: fix 'list_add double add' caused by legacy signal
    interface (git-fixes).

  - mac80211: Always report TX status (bsc#1051510).

  - mac80211: TDLS: fix skb queue/priority assignment
    (bsc#1051510).

  - mac80211: fix TX status reporting for ieee80211s
    (bsc#1051510).

  - mac80211_hwsim: do not omit multicast announce of first
    added radio (bsc#1051510).

  - mach64: fix display corruption on big endian machines
    (bsc#1113722)

  - mach64: fix image corruption due to reading accelerator
    registers (bsc#1113722)

  - mailbox: PCC: handle parse error (bsc#1051510).

  - make sure that __dentry_kill() always invalidates d_seq,
    unhashed or not (git-fixes).

  - md/raid10: fix that replacement cannot complete recovery
    after reassemble (git-fixes).

  - md/raid1: add error handling of read error from FailFast
    device (git-fixes).

  - md/raid5-cache: disable reshape completely (git-fixes).

  - md/raid5: fix data corruption of replacements after
    originals dropped (git-fixes).

  - md: fix NULL dereference of mddev->pers in
    remove_and_add_spares() (git-fixes).

  - memory_hotplug: cond_resched in __remove_pages
    (bnc#1114178).

  - mfd: menelaus: Fix possible race condition and leak
    (bsc#1051510).

  - mfd: omap-usb-host: Fix dts probe of children
    (bsc#1051510).

  - mlxsw: spectrum: Fix IP2ME CPU policer configuration
    (networking-stable-18_11_21).

  - mm: handle no memcg case in memcg_kmem_charge() properly
    (bnc#1113677).

  - mm: rework memcg kernel stack accounting (bnc#1113677).

  - mmc: dw_mmc-rockchip: correct property names in debug
    (bsc#1051510).

  - mmc: sdhci-pci-o2micro: Add quirk for O2 Micro dev
    0x8620 rev 0x01 (bsc#1051510).

  - modpost: ignore livepatch unresolved relocations ().

  - mount: Do not allow copying MNT_UNBINDABLE|MNT_LOCKED
    mounts (bsc#1117819).

  - mount: Prevent MNT_DETACH from disconnecting locked
    mounts (bsc#1117820).

  - mount: Retest MNT_LOCKED in do_umount (bsc#1117818).

  - neighbour: confirm neigh entries when ARP packet is
    received (networking-stable-18_09_24).

  - net-gro: reset skb->pkt_type in napi_reuse_skb()
    (networking-stable-18_11_21).

  - net/af_iucv: drop inbound packets with invalid flags
    (bnc#1113501, LTC#172679).

  - net/af_iucv: fix skb handling on HiperTransport xmit
    error (bnc#1113501, LTC#172679).

  - net/appletalk: fix minor pointer leak to userspace in
    SIOCFINDIPDDPRT (networking-stable-18_09_24).

  - net/ibmnvic: Fix deadlock problem in reset ().

  - net/ibmvnic: Fix RTNL deadlock during device reset
    (bnc#1115431).

  - net/ipv6: Display all addresses in output of
    /proc/net/if_inet6 (networking-stable-18_10_16).

  - net/ipv6: Fix index counter for unicast addresses in
    in6_dump_addrs (networking-stable-18_11_02).

  - net/mlx5: Check for error in mlx5_attach_interface
    (networking-stable-18_09_18).

  - net/mlx5: E-Switch, Fix memory leak when creating
    switchdev mode FDB tables (networking-stable-18_09_18).

  - net/mlx5: E-Switch, Fix out of bound access when setting
    vport rate (networking-stable-18_10_16).

  - net/mlx5: Fix debugfs cleanup in the device init/remove
    flow (networking-stable-18_09_18).

  - net/mlx5: Fix use-after-free in self-healing flow
    (networking-stable-18_09_18).

  - net/mlx5: Take only bit 24-26 of wqe.pftype_wq for page
    fault type (networking-stable-18_11_02).

  - net/mlx5e: Fix selftest for small MTUs
    (networking-stable-18_11_21).

  - net/mlx5e: Set vlan masks for all offloaded TC rules
    (networking-stable-18_10_16).

  - net/packet: fix packet drop as of virtio gso
    (networking-stable-18_10_16).

  - net/sched: act_pedit: fix dump of extended layered op
    (networking-stable-18_09_11).

  - net/sched: act_sample: fix NULL dereference in the data
    path (networking-stable-18_09_24).

  - net/usb: cancel pending work when unbinding smsc75xx
    (networking-stable-18_10_16).

  - net: aquantia: memory corruption on jumbo frames
    (networking-stable-18_10_16).

  - net: bcmgenet: Poll internal PHY for GENETv5
    (networking-stable-18_11_02).

  - net: bcmgenet: protect stop from timeout
    (networking-stable-18_11_21).

  - net: bcmgenet: use MAC link status for fixed phy
    (networking-stable-18_09_11).

  - net: bridge: remove ipv6 zero address check in mcast
    queries (git-fixes).

  - net: dsa: bcm_sf2: Call setup during switch resume
    (networking-stable-18_10_16).

  - net: dsa: bcm_sf2: Fix unbind ordering
    (networking-stable-18_10_16).

  - net: ena: Fix Kconfig dependency on X86 (bsc#1111696
    bsc#1117561).

  - net: ena: add functions for handling Low Latency Queues
    in ena_com (bsc#1111696 bsc#1117561).

  - net: ena: add functions for handling Low Latency Queues
    in ena_netdev (bsc#1111696 bsc#1117561).

  - net: ena: change rx copybreak default to reduce kernel
    memory pressure (bsc#1111696 bsc#1117561).

  - net: ena: complete host info to match latest ENA spec
    (bsc#1111696 bsc#1117561).

  - net: ena: enable Low Latency Queues (bsc#1111696
    bsc#1117561).

  - net: ena: explicit casting and initialization, and
    clearer error handling (bsc#1111696 bsc#1117561).

  - net: ena: fix NULL dereference due to untimely napi
    initialization (bsc#1111696 bsc#1117561).

  - net: ena: fix auto casting to boolean (bsc#1111696
    bsc#1117561).

  - net: ena: fix compilation error in xtensa architecture
    (bsc#1111696 bsc#1117561).

  - net: ena: fix crash during failed resume from
    hibernation (bsc#1111696 bsc#1117561).

  - net: ena: fix indentations in ena_defs for better
    readability (bsc#1111696 bsc#1117561).

  - net: ena: fix rare bug when failed restart/resume is
    followed by driver removal (bsc#1111696 bsc#1117561).

  - net: ena: fix warning in rmmod caused by double iounmap
    (bsc#1111696 bsc#1117561).

  - net: ena: introduce Low Latency Queues data structures
    according to ENA spec (bsc#1111696 bsc#1117561).

  - net: ena: limit refill Rx threshold to 256 to avoid
    latency issues (bsc#1111696 bsc#1117561).

  - net: ena: minor performance improvement (bsc#1111696
    bsc#1117561).

  - net: ena: remove ndo_poll_controller (bsc#1111696
    bsc#1117561).

  - net: ena: remove redundant parameter in
    ena_com_admin_init() (bsc#1111696 bsc#1117561).

  - net: ena: update driver version to 2.0.1 (bsc#1111696
    bsc#1117561).

  - net: ena: use CSUM_CHECKED device indication to report
    skb's checksum status (bsc#1111696 bsc#1117561).

  - net: fec: do not dump RX FIFO register when not
    available (networking-stable-18_11_02).

  - net: hns: fix for unmapping problem when SMMU is on
    (networking-stable-18_10_16).

  - net: hp100: fix always-true check for link up state
    (networking-stable-18_09_24).

  - net: ibm: fix return type of ndo_start_xmit function ().

  - net: ipmr: fix unresolved entry dumps
    (networking-stable-18_11_02).

  - net: macb: do not disable MDIO bus at open/close time
    (networking-stable-18_09_11).

  - net: mvpp2: Extract the correct ethtype from the skb for
    tx csum offload (networking-stable-18_10_16).

  - net: mvpp2: fix a txq_done race condition
    (networking-stable-18_10_16).

  - net: phy: mdio-gpio: Fix working over slow can_sleep
    GPIOs (networking-stable-18_11_21).

  - net: qca_spi: Fix race condition in spi transfers
    (networking-stable-18_09_18).

  - net: qmi_wwan: add Wistron Neweb D19Q1 (bsc#1051510).

  - net: sched: Fix for duplicate class dump
    (networking-stable-18_11_02).

  - net: sched: Fix memory exposure from short TCA_U32_SEL
    (networking-stable-18_09_11).

  - net: sched: action_ife: take reference to meta module
    (networking-stable-18_09_11).

  - net: sched: gred: pass the right attribute to
    gred_change_table_def() (networking-stable-18_11_02).

  - net: smsc95xx: Fix MTU range
    (networking-stable-18_11_21).

  - net: socket: fix a missing-check bug
    (networking-stable-18_11_02).

  - net: stmmac: Fix stmmac_mdio_reset() when building
    stmmac as modules (networking-stable-18_11_02).

  - net: stmmac: Fixup the tail addr setting in xmit path
    (networking-stable-18_10_16).

  - net: systemport: Fix wake-up interrupt race during
    resume (networking-stable-18_10_16).

  - net: systemport: Protect stop from timeout
    (networking-stable-18_11_21).

  - net: udp: fix handling of CHECKSUM_COMPLETE packets
    (networking-stable-18_11_02).

  - netlabel: check for IPV4MASK in addrinfo_get
    (networking-stable-18_10_16).

  - nfp: wait for posted reconfigs when disabling the device
    (networking-stable-18_09_11).

  - nfs: do not wait on commit in nfs_commit_inode() if
    there were no commit requests (git-fixes).

  - nfsd4: permit layoutget of executable-only files
    (git-fixes).

  - nfsd: CLOSE SHOULD return the invalid special stateid
    for NFSv4.x (x>0) (git-fixes).

  - nfsd: Ensure we check stateid validity in the seqid
    operation checks (git-fixes).

  - nfsd: Fix another OPEN stateid race (git-fixes).

  - nfsd: Fix stateid races between OPEN and CLOSE
    (git-fixes).

  - nfsd: check for use of the closed special stateid
    (git-fixes).

  - nfsd: deal with revoked delegations appropriately
    (git-fixes).

  - nfsd: fix corrupted reply to badly ordered compound
    (git-fixes).

  - nfsd: fix potential use-after-free in
    nfsd4_decode_getdeviceinfo (git-fixes).

  - nfsd: restrict rd_maxcount to svc_max_payload in
    nfsd_encode_readdir (git-fixes).

  - nl80211: Fix possible Spectre-v1 for CQM RSSI thresholds
    (bsc#1051510).

  - nl80211: Fix possible Spectre-v1 for NL80211_TXRATE_HT
    (bsc#1051510).

  - nospec: Include asm/barrier.h dependency (bsc#1114279).

  - nvme: Free ctrl device name on init failure ().

  - ocfs2: fix a misuse a of brelse after failing
    ocfs2_check_dir_entry (bsc#1117817).

  - ocfs2: fix locking for res->tracking and
    dlm->tracking_list (bsc#1117816).

  - ocfs2: fix ocfs2 read block panic (bsc#1117815).

  - ocfs2: free up write context when direct IO failed
    (bsc#1117821).

  - ocfs2: subsystem.su_mutex is required while accessing
    the item->ci_parent (bsc#1117808).

  - openvswitch: Fix push/pop ethernet validation
    (networking-stable-18_11_02).

  - pNFS: Always free the session slot on error in
    nfs4_layoutget_handle_exception (git-fixes).

  - pNFS: Prevent the layout header refcount going to zero
    in pnfs_roc() (git-fixes).

  - pci: dwc: remove duplicate fix References: bsc#1115269
    Patch has been already applied by the following commit:
    9f73db8b7c PCI: dwc: Fix enumeration end when reaching
    root subordinate (bsc#1051510)

  - pcmcia: Implement CLKRUN protocol disabling for Ricoh
    bridges (bsc#1051510).

  - percpu: make this_cpu_generic_read() atomic w.r.t.
    interrupts (bsc#1114279).

  - perf: fix invalid bit in diagnostic entry (git-fixes).

  - pinctrl: at91-pio4: fix has_config check in
    atmel_pctl_dt_subnode_to_map() (bsc#1051510).

  - pinctrl: meson: fix pinconf bias disable (bsc#1051510).

  - pinctrl: qcom: spmi-mpp: Fix drive strength setting
    (bsc#1051510).

  - pinctrl: qcom: spmi-mpp: Fix err handling of
    pmic_mpp_set_mux (bsc#1051510).

  - pinctrl: spmi-mpp: Fix pmic_mpp_config_get() to be
    compliant (bsc#1051510).

  - pinctrl: ssbi-gpio: Fix pm8xxx_pin_config_get() to be
    compliant (bsc#1051510).

  - pipe: match pipe_max_size data type with procfs
    (git-fixes).

  - platform/x86: acerhdf: Add BIOS entry for Gateway LT31
    v1.3307 (bsc#1051510).

  - platform/x86: intel_telemetry: report debugfs failure
    (bsc#1051510).

  - pnfs: Do not release the sequence slot until we've
    processed layoutget on open (git-fixes).

  - power: supply: max8998-charger: Fix platform data
    retrieval (bsc#1051510).

  - powerpc/64s/hash: Do not use PPC_INVALIDATE_ERAT on CPUs
    before POWER9 (bsc#1065729).

  - powerpc/boot: Fix opal console in boot wrapper
    (bsc#1065729).

  - powerpc/kvm/booke: Fix altivec related build break
    (bsc#1061840).

  - powerpc/kvm: Switch kvm pmd allocator to custom
    allocator (bsc#1061840).

  - powerpc/mm/keys: Move pte bits to correct headers
    (bsc#1078248).

  - powerpc/mm: Fix typo in comments (bsc#1065729).

  - powerpc/mm: Rename find_linux_pte_or_hugepte()
    (bsc#1061840).

  - powerpc/npu-dma.c: Fix crash after
    __mmu_notifier_register failure (bsc#1055120).

  - powerpc/perf: Update raw-event code encoding comment for
    power8 (bsc#1065729).

  - powerpc/powernv/ioda: Allocate indirect TCE levels on
    demand (bsc#1061840).

  - powerpc/powernv/ioda: Finish removing explicit max
    window size check (bsc#1061840).

  - powerpc/powernv/ioda: Remove explicit max window size
    check (bsc#1061840).

  - powerpc/powernv/npu: Add lock to prevent race in
    concurrent context init/destroy (bsc#1055120).

  - powerpc/powernv/npu: Do not explicitly flush nmmu tlb
    (bsc#1055120).

  - powerpc/powernv/npu: Fix deadlock in mmio_invalidate()
    (bsc#1055120).

  - powerpc/powernv/npu: Prevent overwriting of
    pnv_npu2_init_contex() callback parameters
    (bsc#1055120).

  - powerpc/powernv/npu: Use flush_all_mm() instead of
    flush_tlb_mm() (bsc#1055120).

  - powerpc/powernv/pci: Work around races in PCI bridge
    enabling (bsc#1055120).

  - powerpc/powernv: Add indirect levels to it_userspace
    (bsc#1061840).

  - powerpc/powernv: Do not select the cpufreq governors
    (bsc#1065729).

  - powerpc/powernv: Fix concurrency issue with
    npu->mmio_atsd_usage (bsc#1055120).

  - powerpc/powernv: Fix opal_event_shutdown() called with
    interrupts disabled (bsc#1065729).

  - powerpc/powernv: Move TCE manupulation code to its own
    file (bsc#1061840).

  - powerpc/powernv: Rework TCE level allocation
    (bsc#1061840).

  - powerpc/pseries/mobility: Extend start/stop topology
    update scope (bsc#1116950, bsc#1115709).

  - powerpc/pseries: Fix DTL buffer registration
    (bsc#1065729).

  - powerpc/pseries: Fix how we iterate over the DTL entries
    (bsc#1065729).

  - powerpc/xive: Move definition of ESB bits (bsc#1061840).

  - powerpc/xmon: Add ISA v3.0 SPRs to SPR dump
    (bsc#1061840).

  - pppoe: fix reception of frames with no mac header
    (networking-stable-18_09_24).

  - printk: Fix panic caused by passing log_buf_len to
    command line (bsc#1117168).

  - provide linux/set_memory.h (bsc#1113295).

  - ptp: fix Spectre v1 vulnerability (bsc#1051510).

  - pwm: lpss: Release runtime-pm reference from the
    driver's remove callback (bsc#1051510).

  - pxa168fb: prepare the clock (bsc#1051510).

  - qmi_wwan: Support dynamic config on Quectel EP06
    (bsc#1051510).

  - qmi_wwan: apply SET_DTR quirk to the SIMCOM shared
    device ID (bsc#1051510).

  - r8169: fix NAPI handling under high load
    (networking-stable-18_11_02).

  - race of lockd inetaddr notifiers vs nlmsvc_rqst change
    (git-fixes).

  - rds: fix two RCU related problems
    (networking-stable-18_09_18).

  - remoteproc: qcom: Fix potential device node leaks
    (bsc#1051510).

  - reset: hisilicon: fix potential NULL pointer dereference
    (bsc#1051510).

  - reset: imx7: Fix always writing bits as 0 (bsc#1051510).

  - resource: Include resource end in walk_*() interfaces
    (bsc#1114279).

  - rpm/kernel-binary.spec.in: add macros.s into
    kernel-*-devel Starting with 4.20-rc1, file
    arch/*/kernel/macros.s is needed to build out of tree
    modules. Add it to kernel-$(flavor)-devel packages if it
    exists.

  - rpm/kernel-binary.spec.in: allow unsupported modules for
    -extra (bsc#1111183). SLE-15 and later only.

  - rpm/kernel-source.spec.in: Add patches.drm for moved DRM
    patches

  - rpm: use syncconfig instead of silentoldconfig where
    available Since mainline commit 0085b4191f3e ('kconfig:
    remove silentoldconfig target'), 'make silentoldconfig'
    can be no longer used. Use 'make syncconfig' instead if
    available.

  - rtnetlink: Disallow FDB configuration for non-Ethernet
    device (networking-stable-18_11_02).

  - rtnetlink: fix rtnl_fdb_dump() for ndmsg header
    (networking-stable-18_10_16).

  - rtnl: limit IFLA_NUM_TX_QUEUES and IFLA_NUM_RX_QUEUES to
    4096 (networking-stable-18_10_16).

  - s390/cpum_sf: Add data entry sizes to sampling trailer
    entry (git-fixes).

  - s390/kvm: fix deadlock when killed by oom (bnc#1113501,
    LTC#172235).

  - s390/mm: Check for valid vma before zapping in
    gmap_discard (git-fixes).

  - s390/mm: correct allocate_pgste proc_handler callback
    (git-fixes).

  - s390/qeth: fix HiperSockets sniffer (bnc#1113501,
    LTC#172953).

  - s390/qeth: handle failure on workqueue creation
    (git-fixes).

  - s390/qeth: report 25Gbit link speed (bnc#1113501,
    LTC#172959).

  - s390/sclp_tty: enable line mode tty even if there is an
    ascii console (git-fixes).

  - s390/sthyi: add cache to store hypervisor info
    (LTC#160415, bsc#1068273).

  - s390/sthyi: add s390_sthyi system call (LTC#160415,
    bsc#1068273).

  - s390/sthyi: reorganize sthyi implementation (LTC#160415,
    bsc#1068273).

  - s390: qeth: Fix potential array overrun in cmd/rc lookup
    (bnc#1113501, LTC#172682).

  - s390: qeth_core_mpc: Use ARRAY_SIZE instead of
    reimplementing its function (bnc#1113501, LTC#172682).

  - s390: revert ELF_ET_DYN_BASE base changes (git-fixes).

  - scripts/git_sort/git_sort.py: add mkp/scsi.git
    4.21/scsi-queue

  - scsi: core: Avoid that SCSI device removal through sysfs
    triggers a deadlock (bsc#1114578).

  - scsi: libsas: remove irq save in sas_ata_qc_issue()
    (bsc#1114580).

  - scsi: lpfc: Correct LCB RJT handling (bsc#1114015).

  - scsi: lpfc: Correct errors accessing fw log
    (bsc#1114015).

  - scsi: lpfc: Correct invalid EQ doorbell write on
    if_type=6 (bsc#1114015).

  - scsi: lpfc: Correct irq handling via locks when taking
    adapter offline (bsc#1114015).

  - scsi: lpfc: Correct loss of fc4 type on remote port
    address change (bsc#1114015).

  - scsi: lpfc: Correct race with abort on completion path
    (bsc#1114015).

  - scsi: lpfc: Correct soft lockup when running mds
    diagnostics (bsc#1114015).

  - scsi: lpfc: Correct speeds on SFP swap (bsc#1114015).

  - scsi: lpfc: Fix GFT_ID and PRLI logic for RSCN
    (bsc#1114015).

  - scsi: lpfc: Fix LOGO/PLOGI handling when triggerd by
    ABTS Timeout event (bsc#1114015).

  - scsi: lpfc: Fix errors in log messages (bsc#1114015).

  - scsi: lpfc: Fix lpfc_sli4_read_config return value check
    (bsc#1114015).

  - scsi: lpfc: Fix odd recovery in duplicate FLOGIs in
    point-to-point (bsc#1114015).

  - scsi: lpfc: Implement GID_PT on Nameserver query to
    support faster failover (bsc#1114015).

  - scsi: lpfc: Raise nvme defaults to support a larger io
    and more connectivity (bsc#1114015).

  - scsi: lpfc: Remove set but not used variable 'sgl_size'
    (bsc#1114015).

  - scsi: lpfc: Reset link or adapter instead of doing
    infinite nameserver PLOGI retry (bsc#1114015).

  - scsi: lpfc: Synchronize access to remoteport via rport
    (bsc#1114015).

  - scsi: lpfc: add Trunking support (bsc#1114015).

  - scsi: lpfc: add support to retrieve firmware logs
    (bsc#1114015).

  - scsi: lpfc: fcoe: Fix link down issue after 1000+ link
    bounces (bsc#1114015).

  - scsi: lpfc: raise sg count for nvme to use available sg
    resources (bsc#1114015).

  - scsi: lpfc: reduce locking when updating statistics
    (bsc#1114015).

  - scsi: lpfc: update driver version to 12.0.0.7
    (bsc#1114015).

  - scsi: lpfc: update driver version to 12.0.0.8
    (bsc#1114015).

  - scsi: qlogicpti: Fix an error handling path in
    'qpti_sbus_probe()' (bsc#1114581).

  - scsi: scsi_transport_srp: Fix shost to rport translation
    (bsc#1114582).

  - scsi: sg: fix minor memory leak in error path
    (bsc#1114584).

  - scsi: sysfs: Introduce
    sysfs_(un,)break_active_protection() (bsc#1114578).

  - scsi: target/tcm_loop: Avoid that static checkers warn
    about dead code (bsc#1114577).

  - scsi: target: Fix fortify_panic kernel exception
    (bsc#1114576).

  - scsi: target: tcmu: add read length support
    (bsc#1097755).

  - sctp: fix race on sctp_id2asoc
    (networking-stable-18_11_02).

  - sctp: fix strchange_flags name for Stream Change Event
    (networking-stable-18_11_21).

  - sctp: hold transport before accessing its asoc in
    sctp_transport_get_next (networking-stable-18_09_11).

  - sctp: not allow to set asoc prsctp_enable by sockopt
    (networking-stable-18_11_21).

  - sctp: not increase stream's incnt before sending
    addstrm_in request (networking-stable-18_11_21).

  - skip LAYOUTRETURN if layout is invalid (git-fixes).

  - soc: fsl: qbman: qman: avoid allocating from non
    existing gen_pool (bsc#1051510).

  - soc: ti: QMSS: Fix usage of irq_set_affinity_hint
    (bsc#1051510).

  - staging: rtl8723bs: Fix the return value in case of
    error in 'rtw_wx_read32()' (bsc#1051510).

  - staging: vchiq_arm: fix compat
    VCHIQ_IOC_AWAIT_COMPLETION (bsc#1051510).

  - staging:iio:ad7606: fix voltage scales (bsc#1051510).

  - sunrpc: Do not use stack buffer with scatterlist
    (git-fixes).

  - sunrpc: Fix rpc_task_begin trace point (git-fixes).

  - target: fix buffer offset in
    core_scsi3_pri_read_full_status (bsc1117349).

  - tcp: do not restart timewait timer on rst reception
    (networking-stable-18_09_11).

  - test_firmware: fix error return getting clobbered
    (bsc#1051510).

  - tg3: Add PHY reset for 5717/5719/5720 in change ring and
    flow control paths (networking-stable-18_11_21).

  - thermal: bcm2835: enable hwmon explicitly (bsc#1108468).

  - thermal: da9062/61: Prevent hardware access during
    system suspend (bsc#1051510).

  - thermal: rcar_thermal: Prevent hardware access during
    system suspend (bsc#1051510).

  - tipc: do not assume linear buffer when reading ancillary
    data (networking-stable-18_11_21).

  - tipc: fix a missing rhashtable_walk_exit()
    (networking-stable-18_09_11).

  - tipc: fix flow control accounting for implicit connect
    (networking-stable-18_10_16).

  - tpm2-cmd: allow more attempts for selftest execution
    (bsc#1082555).

  - tpm: React correctly to RC_TESTING from TPM 2.0 self
    tests (bsc#1082555).

  - tpm: Restore functionality to xen vtpm driver
    (bsc#1082555).

  - tpm: Trigger only missing TPM 2.0 self tests
    (bsc#1082555).

  - tpm: Use dynamic delay to wait for TPM 2.0 self test
    result (bsc#1082555).

  - tpm: add retry logic (bsc#1082555).

  - tpm: consolidate the TPM startup code (bsc#1082555).

  - tpm: do not suspend/resume if power stays on
    (bsc#1082555).

  - tpm: fix intermittent failure with self tests
    (bsc#1082555).

  - tpm: fix response size validation in tpm_get_random()
    (bsc#1082555).

  - tpm: move endianness conversion of TPM_TAG_RQU_COMMAND
    to tpm_input_header (bsc#1082555).

  - tpm: move endianness conversion of ordinals to
    tpm_input_header (bsc#1082555).

  - tpm: move the delay_msec increment after sleep in
    tpm_transmit() (bsc#1082555).

  - tpm: replace msleep() with usleep_range() in TPM 1.2/2.0
    generic drivers (bsc#1082555).

  - tpm: self test failure should not cause suspend to fail
    (bsc#1082555).

  - tpm: tpm-interface: fix tpm_transmit/_cmd kdoc
    (bsc#1082555).

  - tpm: use tpm2_pcr_read() in tpm2_do_selftest()
    (bsc#1082555).

  - tpm: use tpm_buf functions in tpm2_pcr_read()
    (bsc#1082555).

  - tracing: Apply trace_clock changes to instance max
    buffer (bsc#1117188).

  - tracing: Erase irqsoff trace with empty write
    (bsc#1117189).

  - tty: Do not block on IO when ldisc change is pending
    (bnc#1105428).

  - tty: check name length in tty_find_polling_driver()
    (bsc#1051510).

  - tty: wipe buffer (bsc#1051510).

  - tty: wipe buffer if not echoing data (bsc#1051510).

  - tun: Consistently configure generic netdev params via
    rtnetlink (bsc#1051510).

  - tuntap: fix multiqueue rx (networking-stable-18_11_21).

  - udp4: fix IP_CMSG_CHECKSUM for connected sockets
    (networking-stable-18_09_24).

  - udp6: add missing checks on edumux packet processing
    (networking-stable-18_09_24).

  - udp6: fix encap return code for resubmitting
    (git-fixes).

  - uio: Fix an Oops on load (bsc#1051510).

  - uio: ensure class is registered before devices
    (bsc#1051510).

  - uio: make symbol 'uio_class_registered' static
    (bsc#1051510).

  - usb: cdc-acm: add entry for Hiro (Conexant) modem
    (bsc#1051510).

  - usb: core: Fix hub port connection events lost
    (bsc#1051510).

  - usb: dwc2: host: Do not retry NAKed transactions right
    away (bsc#1114385).

  - usb: dwc2: host: do not delay retries for CONTROL IN
    transfers (bsc#1114385).

  - usb: dwc3: core: Clean up ULPI device (bsc#1051510).

  - usb: dwc3: gadget: Properly check last unaligned/zero
    chain TRB (bsc#1051510).

  - usb: dwc3: gadget: fix ISOC TRB type on unaligned
    transfers (bsc#1051510).

  - usb: gadget: storage: Fix Spectre v1 vulnerability
    (bsc#1051510).

  - usb: gadget: u_ether: fix unsafe list iteration
    (bsc#1051510).

  - usb: gadget: udc: atmel: handle at91sam9rl PMC
    (bsc#1051510).

  - usb: host: ohci-at91: fix request of irq for optional
    gpio (bsc#1051510).

  - usb: quirks: Add delay-init quirk for Corsair K70 LUX
    RGB (bsc#1051510).

  - usb: xhci: fix timeout for transition from RExit to U0
    (bsc#1051510).

  - usbip:vudc: BUG kmalloc-2048 (Not tainted): Poison
    overwritten (bsc#1051510).

  - usbnet: smsc95xx: disable carrier check while suspending
    (bsc#1051510).

  - vfs: fix freeze protection in mnt_want_write_file() for
    overlayfs (git-fixes).

  - vhost/scsi: truncate T10 PI iov_iter to prot_bytes
    (bsc#1051510).

  - vhost: Fix Spectre V1 vulnerability (bsc#1051510).

  - virtio_net: avoid using netif_tx_disable() for
    serializing tx routine (networking-stable-18_11_02).

  - w1: omap-hdq: fix missing bus unregister at removal
    (bsc#1051510).

  - x86, hibernate: Fix nosave_regions setup for hibernation
    (bsc#1110006).

  - x86/MCE: Make correctable error detection look at the
    Deferred bit (bsc#1114279).

  - x86/corruption-check: Fix panic in
    memory_corruption_check() when boot option without value
    is provided (bsc#1110006).

  - x86/cpu/vmware: Do not trace vmware_sched_clock()
    (bsc#1114279).

  - x86/irq: implement
    irq_data_get_effective_affinity_mask() for v4.12
    (bsc#1109772).

  - x86/kexec: Correct KEXEC_BACKUP_SRC_END off-by-one error
    (bsc#1114279).

  - x86/ldt: Remove unused variable in map_ldt_struct()
    (bsc#1114279).

  - x86/ldt: Split out sanity check in map_ldt_struct()
    (bsc#1114279).

  - x86/ldt: Unmap PTEs for the slot before freeing LDT
    pages (bsc#1114279).

  - x86/mm/pat: Disable preemption around __flush_tlb_all()
    (bsc#1114279).

  - x86/speculation: Support Enhanced IBRS on future CPUs
    ().

  - x86/xen: Fix boot loader version reported for PVH guests
    (bnc#1065600).

  - xen-swiotlb: use actually allocated size on check
    physical continuous (bnc#1065600).

  - xen/balloon: Support xend-based toolstack (bnc#1065600).

  - xen/blkfront: avoid NULL blkfront_info dereference on
    device removal (bsc#1111062).

  - xen/netfront: do not bug in case of too many frags
    (bnc#1104824).

  - xen/pvh: do not try to unplug emulated devices
    (bnc#1065600).

  - xen/pvh: increase early stack size (bnc#1065600).

  - xen: fix race in xen_qlock_wait() (bnc#1107256).

  - xen: fix xen_qlock_wait() (bnc#1107256).

  - xen: make xen_qlock_wait() nestable (bnc#1107256).

  - xfs: Fix error code in 'xfs_ioc_getbmap()' (git-fixes).

  - xfs: Properly detect when DAX won't be used on any
    device (bsc#1115976).

  - xhci: Add check for invalid byte size error when UAS
    devices are connected (bsc#1051510).

  - xhci: Fix leaking USB3 shared_hcd at xhci removal
    (bsc#1051510).

  - xprtrdma: Do not defer fencing an async RPC's chunks
    (git-fixes)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/325723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/326265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/326521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/326564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/326849"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-base-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-debugsource-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-debug-devel-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-base-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-debugsource-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-default-devel-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-devel-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-docs-html-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-debugsource-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-macros-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-build-debugsource-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-obs-qa-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-source-vanilla-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-syms-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debuginfo-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-debugsource-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-4.12.14-lp150.12.28.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp150.12.28.1") ) flag++;

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
