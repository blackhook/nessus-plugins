#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-3.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105636);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-17805", "CVE-2017-17806", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-3) (Meltdown) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-3 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.104 to receive
various security and bugfixes.

This update adds mitigations for various side channel attacks against
modern CPUs that could disclose content of otherwise unreadable memory
(bnc#1068032).

  - CVE-2017-5753 / 'SpectreAttack': Local attackers on
    systems with modern CPUs featuring deep instruction
    pipelining could use attacker controllable speculative
    execution over code patterns in the Linux Kernel to leak
    content from otherwise not readable memory in the same
    address space, allowing retrieval of passwords,
    cryptographic keys and other secrets.

    This problem is mitigated by adding speculative fencing
    on affected code paths throughout the Linux kernel.

  - CVE-2017-5715 / 'SpectreAttack': Local attackers on
    systems with modern CPUs featuring branch prediction
    could use mispredicted branches to speculatively execute
    code patterns that in turn could be made to leak other
    non-readable content in the same address space, an
    attack similar to CVE-2017-5753.

    This problem is mitigated by disabling predictive
    branches, depending on CPU architecture either by
    firmware updates and/or fixes in the user-kernel
    privilege boundaries.

    Please also check with your CPU / Hardware vendor on
    updated firmware or BIOS images regarding this issue.

    As this feature can have a performance impact, it can be
    disabled using the 'nospec' kernel commandline option.

  - CVE-2017-5754 / 'MeltdownAttack': Local attackers on
    systems with modern CPUs featuring deep instruction
    pipelining could use code patterns in userspace to
    speculative executive code that would read otherwise
    read protected memory, an attack similar to
    CVE-2017-5753.

    This problem is mitigated by unmapping the Linux Kernel
    from the user address space during user code execution,
    following a approach called 'KAISER'. The terms used
    here are 'KAISER' / 'Kernel Address Isolation' and 'PTI'
    / 'Page Table Isolation'.

    Note that this is only done on affected platforms.

    This feature can be enabled / disabled by the
    'pti=[on|off|auto]' or 'nopti' commandline options.

The following security bugs were fixed :

  - CVE-2017-17806: The HMAC implementation (crypto/hmac.c)
    in the Linux kernel did not validate that the underlying
    cryptographic hash algorithm is unkeyed, allowing a
    local attacker able to use the AF_ALG-based hash
    interface (CONFIG_CRYPTO_USER_API_HASH) and the SHA-3
    hash algorithm (CONFIG_CRYPTO_SHA3) to cause a kernel
    stack-based buffer overflow by executing a crafted
    sequence of system calls that encounter a missing SHA-3
    initialization (bnc#1073874).

  - CVE-2017-17805: The Salsa20 encryption algorithm in the
    Linux kernel did not correctly handle zero-length
    inputs, allowing a local attacker able to use the
    AF_ALG-based skcipher interface
    (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of
    service (uninitialized-memory free and kernel crash) or
    have unspecified other impact by executing a crafted
    sequence of system calls that use the blkcipher_walk
    API. Both the generic implementation
    (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 were
    vulnerable (bnc#1073792).

The following non-security bugs were fixed :

  - Add undefine _unique_build_ids (bsc#964063)

  - alsa: hda - Add HP ZBook 15u G3 Conexant CX20724 GPIO
    mute leds (bsc#1031717).

  - alsa: hda - Add MIC_NO_PRESENCE fixup for 2 HP machines
    (bsc#1031717).

  - alsa: hda - Add mute led support for HP EliteBook 840 G3
    (bsc#1031717).

  - alsa: hda - Add mute led support for HP ProBook 440 G4
    (bsc#1031717).

  - alsa: hda - add support for docking station for HP 820
    G2 (bsc#1031717).

  - alsa: hda - add support for docking station for HP 840
    G3 (bsc#1031717).

  - alsa: hda - change the location for one mic on a Lenovo
    machine (bsc#1031717).

  - alsa: hda: Drop useless WARN_ON() (bsc#1031717).

  - alsa: hda - Fix click noises on Samsung Ativ Book 8
    (bsc#1031717).

  - alsa: hda - fix headset mic detection issue on a Dell
    machine (bsc#1031717).

  - alsa: hda - fix headset mic problem for Dell machines
    with alc274 (bsc#1031717).

  - alsa: hda - Fix headset microphone detection for ASUS
    N551 and N751 (bsc#1031717).

  - alsa: hda - Fix mic regression by ASRock mobo fixup
    (bsc#1031717).

  - alsa: hda - Fix missing COEF init for ALC225/295/299
    (bsc#1031717).

  - alsa: hda - Fix surround output pins for ASRock B150M
    mobo (bsc#1031717).

  - alsa: hda - On-board speaker fixup on ACER Veriton
    (bsc#1031717).

  - alsa: hda/realtek - Add ALC256 HP depop function
    (bsc#1031717).

  - alsa: hda/realtek - Add default procedure for suspend
    and resume state (bsc#1031717).

  - alsa: hda/realtek - Add support for Acer Aspire E5-475
    headset mic (bsc#1031717).

  - alsa: hda/realtek - Add support for ALC1220
    (bsc#1031717).

  - alsa: hda/realtek - Add support for headset MIC for
    ALC622 (bsc#1031717).

  - alsa: hda/realtek - ALC891 headset mode for Dell
    (bsc#1031717).

  - alsa: hda/realtek - change the location for one of two
    front microphones (bsc#1031717).

  - alsa: hda/realtek - Enable jack detection function for
    Intel ALC700 (bsc#1031717).

  - alsa: hda/realtek - Fix ALC275 no sound issue
    (bsc#1031717).

  - alsa: hda/realtek - Fix Dell AIO LineOut issue
    (bsc#1031717).

  - alsa: hda/realtek - Fix headset and mic on several Asus
    laptops with ALC256 (bsc#1031717).

  - alsa: hda/realtek - Fix headset mic and speaker on Asus
    X441SA/X441UV (bsc#1031717).

  - alsa: hda/realtek - fix headset mic detection for MSI
    MS-B120 (bsc#1031717).

  - alsa: hda/realtek - Fix headset mic on several Asus
    laptops with ALC255 (bsc#1031717).

  - alsa: hda/realtek - Fix pincfg for Dell XPS 13 9370
    (bsc#1031717).

  - alsa: hda/realtek - Fix speaker support for Asus AiO
    ZN270IE (bsc#1031717).

  - alsa: hda/realtek - Fix typo of pincfg for Dell quirk
    (bsc#1031717).

  - alsa: hda/realtek - New codec device ID for ALC1220
    (bsc#1031717).

  - alsa: hda/realtek - New codecs support for
    ALC215/ALC285/ALC289 (bsc#1031717).

  - alsa: hda/realtek - New codec support for ALC257
    (bsc#1031717).

  - alsa: hda/realtek - New codec support of ALC1220
    (bsc#1031717).

  - alsa: hda/realtek - No loopback on ALC225/ALC295 codec
    (bsc#1031717).

  - alsa: hda/realtek - Remove ALC285 device ID
    (bsc#1031717).

  - alsa: hda/realtek - Support Dell headset mode for
    ALC3271 (bsc#1031717).

  - alsa: hda/realtek - Support headset mode for
    ALC234/ALC274/ALC294 (bsc#1031717).

  - alsa: hda/realtek - There is no loopback mixer in the
    ALC234/274/294 (bsc#1031717).

  - alsa: hda/realtek - Update headset mode for ALC225
    (bsc#1031717).

  - alsa: hda/realtek - Update headset mode for ALC298
    (bsc#1031717).

  - alsa: hda - Skip Realtek SKU check for Lenovo machines
    (bsc#1031717).

  - alsa: pcm: prevent UAF in snd_pcm_info (bsc#1031717).

  - alsa: rawmidi: Avoid racy info ioctl via ctl device
    (bsc#1031717).

  - alsa: seq: Remove spurious WARN_ON() at timer check
    (bsc#1031717).

  - alsa: usb-audio: Add check return value for usb_string()
    (bsc#1031717).

  - alsa: usb-audio: Fix out-of-bound error (bsc#1031717).

  - alsa: usb-audio: Fix the missing ctl name suffix at
    parsing SU (bsc#1031717).

  - Always sign validate_negotiate_info reqs (bsc#1071009,
    fate#324404).

  - apei / ERST: Fix missing error handling in erst_reader()
    (bsc#1072556).

  - arm: dts: omap3: logicpd-torpedo-37xx-devkit: Fix MMC1
    cd-gpio (bnc#1012382).

  - arm: Hide finish_arch_post_lock_switch() from modules
    (bsc#1068032).

  - asoc: fsl_ssi: AC'97 ops need regmap, clock and cleaning
    up on failure (bsc#1031717).

  - asoc: twl4030: fix child-node lookup (bsc#1031717).

  - asoc: wm_adsp: Fix validation of firmware and coeff
    lengths (bsc#1031717).

  - autofs: fix careless error in recent commit (bnc#1012382
    bsc#1065180).

  - bcache: Fix building error on MIPS (bnc#1012382).

  - bpf: prevent speculative execution in eBPF interpreter
    (bnc#1068032).

  - btrfs: clear space cache inode generation always
    (bnc#1012382).

  - carl9170: prevent speculative execution (bnc#1068032).

  - Check cmdline_find_option() retval properly and use
    boot_cpu_has().

  - cw1200: prevent speculative execution (bnc#1068032).

  - drm/radeon: fix atombios on big endian (bnc#1012382).

  - e1000e: Avoid receiver overrun interrupt bursts
    (bsc#969470 FATE#319819).

  - e1000e: Fix e1000_check_for_copper_link_ich8lan return
    value (bsc#1073809).

  - eeprom: at24: check at24_read/write arguments
    (bnc#1012382).

  - Fix leak of validate_negotiate_info resp (bsc#1071009,
    fate#324404).

  - Fix NULL pointer deref in SMB2_tcon() (bsc#1071009,
    fate#324404).

  - Fix validate_negotiate_info uninitialized mem
    (bsc#1071009, fate#324404).

  - fs: prevent speculative execution (bnc#1068032).

  - genwqe: Take R/W permissions into account when dealing
    with memory pages (bsc#1073090).

  - ibmvnic: Include header descriptor support for ARP
    packets (bsc#1073912).

  - ibmvnic: Increase maximum number of RX/TX queues
    (bsc#1073912).

  - ibmvnic: Rename IBMVNIC_MAX_TX_QUEUES to
    IBMVNIC_MAX_QUEUES (bsc#1073912).

  - ipv6: prevent speculative execution (bnc#1068032).

  - kabi fix for new hash_cred function (bsc#1012917).

  - kaiser: add 'nokaiser' boot option, using ALTERNATIVE.

  - kaiser: align addition to x86/mm/Makefile.

  - kaiser: asm/tlbflush.h handle noPGE at lower level.

  - kaiser: cleanups while trying for gold link.

  - kaiser: Disable on Xen PV.

  - kaiser: do not set _PAGE_NX on pgd_none.

  - kaiser: drop is_atomic arg to kaiser_pagetable_walk().

  - kaiser: enhanced by kernel and user PCIDs.

  - kaiser: ENOMEM if kaiser_pagetable_walk() NULL.

  - kaiser: fix build and FIXME in alloc_ldt_struct().

  - kaiser: fix perf crashes.

  - kaiser: fix regs to do_nmi() ifndef CONFIG_KAISER.

  - kaiser: fix unlikely error in alloc_ldt_struct().

  - kaiser: KAISER depends on SMP.

  - kaiser: kaiser_flush_tlb_on_return_to_user() check PCID.

  - kaiser: kaiser_remove_mapping() move along the pgd.

  - kaiser: Kernel Address Isolation.

  - kaiser: load_new_mm_cr3() let SWITCH_USER_CR3 flush.

  - kaiser: load_new_mm_cr3() let SWITCH_USER_CR3 flush
    user.

  - kaiser: name that 0x1000 KAISER_SHADOW_PGD_OFFSET.

  - kaiser: paranoid_entry pass cr3 need to paranoid_exit.

  - kaiser: PCID 0 for kernel and 128 for user.

  - kaiser: _pgd_alloc() without __GFP_REPEAT to avoid
    stalls.

  - kaiser: stack map PAGE_SIZE at THREAD_SIZE-PAGE_SIZE.

  - kaiser: tidied up asm/kaiser.h somewhat.

  - kaiser: tidied up kaiser_add/remove_mapping slightly.

  - kaiser: use ALTERNATIVE instead of x86_cr3_pcid_noflush.

  - kaiser: vmstat show NR_KAISERTABLE as nr_overhead.

  - kaiser: x86_cr3_pcid_noflush and x86_cr3_pcid_user.

  - kvm: SVM: Do not intercept new speculative control MSRs
    (bsc#1068032).

  - kvm: x86: Add speculative control CPUID support for
    guests (bsc#1068032).

  - kvm: x86: Exit to user-mode on #UD intercept when
    emulator requires (bnc#1012382).

  - kvm: x86: inject exceptions produced by x86_decode_insn
    (bnc#1012382).

  - kvm: x86: pvclock: Handle first-time write to
    pvclock-page contains random junk (bnc#1012382).

  - locking/barriers: introduce new memory barrier gmb()
    (bnc#1068032).

  - mmc: core: Do not leave the block driver in a suspended
    state (bnc#1012382).

  - mm/mmu_context, sched/core: Fix mmu_context.h assumption
    (bsc#1068032).

  - mtd: nand: Fix writing mtdoops to nand flash
    (bnc#1012382).

  - netlink: add a start callback for starting a netlink
    dump (bnc#1012382).

  - net: mpls: prevent speculative execution (bnc#1068032).

  - nfsd: Fix another OPEN stateid race (bnc#1012382).

  - nfsd: Fix stateid races between OPEN and CLOSE
    (bnc#1012382).

  - nfsd: Make init_open_stateid() a bit more whole
    (bnc#1012382).

  - nfs: improve shinking of access cache (bsc#1012917).

  - nfs: revalidate '.' etc correctly on 'open'
    (bsc#1068951).

  - nfs: revalidate '.' etc correctly on 'open' (git-fixes).
    Fix References tag.

  - nfsv4: always set NFS_LOCK_LOST when a lock is lost
    (bsc#1068951).

  - p54: prevent speculative execution (bnc#1068032).

  - powerpc/barrier: add gmb.

  - powerpc: Secure memory rfi flush (bsc#1068032).

  - ptrace: Add a new thread access check (bsc#1068032).

  - qla2xxx: prevent speculative execution (bnc#1068032).

  - Redo encryption backport to fix pkt signing
    (bsc#1071009, fate#324404).

  - Revert 'drm/radeon: dont switch vt on suspend'
    (bnc#1012382).

  - Revert 'ipsec: Fix aborted xfrm policy dump crash'
    (kabi).

  - Revert 'netlink: add a start callback for starting a
    netlink dump' (kabi).

  - s390: add ppa to system call and program check path
    (bsc#1068032).

  - s390: introduce CPU alternatives.

  - s390: introduce CPU alternatives (bsc#1068032).

  - s390/spinlock: add gmb memory barrier

  - s390/spinlock: add gmb memory barrier (bsc#1068032).

  - s390/spinlock: add ppa to system call path Signoff the
    s390 patches.

  - sched/core: Add switch_mm_irqs_off() and use it in the
    scheduler (bsc#1068032).

  - sched/core: Idle_task_exit() shouldn't use
    switch_mm_irqs_off() (bsc#1068032).

  - sched/rt: Do not pull from current CPU if only one CPU
    to pull (bnc#1022476).

  - scsi_dh_alua: skip RTPG for devices only supporting
    active/optimized (bsc#1064311).

  - scsi_scan: Exit loop if TUR to LUN0 fails with 0x05/0x25
    (bsc#1063043). This is specific to FUJITSU ETERNUS_DX*
    targets. They can return 'Illegal Request - Logical unit
    not supported' and processing should leave the timeout
    loop in this case.

  - scsi: ses: check return code from ses_recv_diag()
    (bsc#1039616).

  - scsi: ses: Fixup error message 'failed to get diagnostic
    page 0xffffffea' (bsc#1039616).

  - scsi: ses: Fix wrong page error (bsc#1039616).

  - scsi: ses: make page2 support optional (bsc#1039616).

  - smb2: Fix share type handling (bnc#1074392).

  - sunrpc: add auth_unix hash_cred() function
    (bsc#1012917).

  - sunrpc: add generic_auth hash_cred() function
    (bsc#1012917).

  - sunrpc: add hash_cred() function to rpc_authops struct
    (bsc#1012917).

  - sunrpc: add RPCSEC_GSS hash_cred() function
    (bsc#1012917).

  - sunrpc: replace generic auth_cred hash with
    auth-specific function (bsc#1012917).

  - sunrpc: use supplimental groups in auth hash
    (bsc#1012917).

  - Thermal/int340x: prevent speculative execution
    (bnc#1068032).

  - udf: prevent speculative execution (bnc#1068032).

  - usb: host: fix incorrect updating of offset
    (bsc#1047487).

  - userns: prevent speculative execution (bnc#1068032).

  - uvcvideo: prevent speculative execution (bnc#1068032).

  - vxlan: correctly handle ipv6.disable module parameter
    (bsc#1072962).

  - x86/boot: Add early cmdline parsing for options with
    arguments.

  - x86/CPU/AMD: Add speculative control support for AMD
    (bsc#1068032).

  - x86/CPU/AMD: Make the LFENCE instruction serialized
    (bsc#1068032).

  - x86/CPU/AMD: Remove now unused definition of
    MFENCE_RDTSC feature (bsc#1068032).

  - x86/CPU: Check speculation control CPUID bit
    (bsc#1068032).

  - x86/efi-bgrt: Fix kernel panic when mapping BGRT data
    (bnc#1012382).

  - x86/efi-bgrt: Replace early_memremap() with memremap()
    (bnc#1012382).

  - x86/efi: Build our own page table structures
    (bnc#1012382).

  - x86/efi: Hoist page table switching code into
    efi_call_virt() (bnc#1012382).

  - x86/enter: Add macros to set/clear IBRS and set IBPB
    (bsc#1068032).

  - x86/entry: Add a function to overwrite the RSB
    (bsc#1068032).

  - x86/entry: Stuff RSB for entry to kernel for non-SMEP
    platform (bsc#1068032).

  - x86/entry: Use IBRS on entry to kernel space
    (bsc#1068032).

  - x86/feature: Enable the x86 feature to control
    Speculation (bsc#1068032).

  - x86/idle: Disable IBRS when offlining a CPU and
    re-enable on wakeup (bsc#1068032).

  - x86/idle: Toggle IBRS when going idle (bsc#1068032).

  - x86/kaiser: Check boottime cmdline params.

  - x86/kaiser: Move feature detection up (bsc#1068032).

  - x86/kaiser: Reenable PARAVIRT.

  - x86/kaiser: Rename and simplify X86_FEATURE_KAISER
    handling.

  - x86/kvm: Add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD to
    kvm (bsc#1068032).

  - x86/kvm: Flush IBP when switching VMs (bsc#1068032).

  - x86/kvm: Pad RSB on VM transition (bsc#1068032).

  - x86/kvm: Toggle IBRS on VM entry and exit (bsc#1068032).

  - x86/mm/64: Fix reboot interaction with CR4.PCIDE
    (bsc#1068032).

  - x86/mm: Add a 'noinvpcid' boot option to turn off
    INVPCID (bsc#1068032).

  - x86/mm: Add INVPCID helpers (bsc#1068032).

  - x86/mm: Add the 'nopcid' boot option to turn off PCID
    (bsc#1068032).

  - x86/mm: Build arch/x86/mm/tlb.c even on !SMP
    (bsc#1068032).

  - x86/mm: Enable CR4.PCIDE on supported systems
    (bsc#1068032).

  - x86/mm: Fix INVPCID asm constraint (bsc#1068032).

  - x86/mm: If INVPCID is available, use it to flush global
    mappings (bsc#1068032).

  - x86/mm: Make flush_tlb_mm_range() more predictable
    (bsc#1068032).

  - x86/mm: Only set IBPB when the new thread cannot ptrace
    current thread (bsc#1068032).

  - x86/mm/pat: Ensure cpa->pfn only contains page frame
    numbers (bnc#1012382).

  - x86/mm: Reimplement flush_tlb_page() using
    flush_tlb_mm_range() (bsc#1068032).

  - x86/mm: Remove flush_tlb() and flush_tlb_current_task()
    (bsc#1068032).

  - x86/mm: Remove the UP asm/tlbflush.h code, always use
    the (formerly) SMP code (bsc#1068032).

  - x86/mm, sched/core: Turn off IRQs in switch_mm()
    (bsc#1068032).

  - x86/mm, sched/core: Uninline switch_mm() (bsc#1068032).

  - x86/mm: Set IBPB upon context switch (bsc#1068032).

  - x86/MSR: Move native_*msr(.. u64) to msr.h
    (bsc#1068032).

  - x86/paravirt: Dont patch flush_tlb_single (bsc#1068032).

  - x86/spec: Add IBRS control functions (bsc#1068032).

  - x86/spec: Add 'nospec' chicken bit (bsc#1068032).

  - x86/spec: Check CPUID direclty post microcode reload to
    support IBPB feature (bsc#1068032).

  - x86/spec_ctrl: Add an Indirect Branch Predictor barrier
    (bsc#1068032).

  - x86/spec_ctrl: Check whether IBPB is enabled before
    using it (bsc#1068032).

  - x86/spec_ctrl: Check whether IBRS is enabled before
    using it (bsc#1068032).

  - x86/svm: Add code to clear registers on VM exit
    (bsc#1068032).

  - x86/svm: Clobber the RSB on VM exit (bsc#1068032).

  - x86/svm: Set IBPB when running a different VCPU
    (bsc#1068032).

  - x86/svm: Set IBRS value on VM entry and exit
    (bsc#1068032)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074392"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969470"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.104-18.44.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.104-18.44.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
