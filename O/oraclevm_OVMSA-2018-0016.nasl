#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0016.
#

include("compat.inc");

if (description)
{
  script_id(106524);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2015-5157", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_bugtraq_id(76005);
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2018-0016) (Meltdown) (Spectre)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - x86: Add another set of MSR accessor functions (Borislav
    Petkov) [Orabug: 27444923] (CVE-2017-5753)

  - userns: prevent speculative execution (Elena Reshetova)
    [Orabug: 27444923] (CVE-2017-5753)

  - udf: prevent speculative execution (Elena Reshetova)
    [Orabug: 27444923] (CVE-2017-5753)

  - fs: prevent speculative execution (Elena Reshetova)
    [Orabug: 27444923] (CVE-2017-5753)

  - qla2xxx: prevent speculative execution (Elena Reshetova)
    [Orabug: 27444923] (CVE-2017-5753)

  - p54: prevent speculative execution (Elena Reshetova)
    [Orabug: 27444923] (CVE-2017-5753)

  - carl9170: prevent speculative execution (Elena
    Reshetova) [Orabug: 27444923] (CVE-2017-5753)

  - uvcvideo: prevent speculative execution (Elena
    Reshetova) [Orabug: 27444923] (CVE-2017-5753)

  - locking/barriers: introduce new observable speculation
    barrier (Elena Reshetova) [Orabug: 27444923]
    (CVE-2017-5753)

  - x86/cpu/AMD: Remove now unused definition of
    MFENCE_RDTSC feature (Elena Reshetova) [Orabug:
    27444923] (CVE-2017-5753)

  - x86/cpu/AMD: Make the LFENCE instruction serialized
    (Elena Reshetova) [Orabug: 27444923] (CVE-2017-5753)

  - x86/rsb: add comment specifying why we skip STUFF_RSB
    (Ankur Arora) [Orabug: 27451658] (CVE-2017-5715)

  - x86/rsb: make STUFF_RSB jmp labels more robust (Ankur
    Arora) [Orabug: 27451658] (CVE-2017-5715)

  - x86/spec: Also print IBRS if IBPB is disabled. (Konrad
    Rzeszutek Wilk) (CVE-2017-5715)

  - x86/spectre: Drop the warning about ibrs being obsolete.
    (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - Add set_ibrs_disabled and set_ibpb_disabled (Konrad
    Rzeszutek Wilk) [Orabug: 27376697] (CVE-2017-5715)

  - x86/spec: Don't print the Missing arguments for option
    spectre_v2 (Konrad Rzeszutek Wilk) [Orabug: 27376697]
    (CVE-2017-5715)

  - x86/boot: Add early cmdline parsing for options with
    arguments (Tom Lendacky) [Orabug: 27376697]
    (CVE-2017-5715)

  - x86, boot: Carve out early cmdline parsing function
    (Borislav Petkov) [Orabug: 27376697] - x86: Add
    command-line options 'spectre_v2' and 'nospectre_v2'
    (Kanth Ghatraju) [Orabug: 27376697] (CVE-2017-5715)

  - x86: Fix kABI build breakage (Konrad Rzeszutek Wilk)
    [Orabug: 27376697] (CVE-2017-5715)

  - x86/mm: Only set IBPB when the new thread cannot ptrace
    current thread (Konrad Rzeszutek Wilk) [Orabug:
    27376697] (CVE-2017-5715)

  - x86: Use PRED_CMD MSR when ibpb is enabled (Konrad
    Rzeszutek Wilk) [Orabug: 27376697] (CVE-2017-5715)

  - x86/mm: Set IBPB upon context switch (Brian Maly)
    [Orabug: 27376697] (CVE-2017-5715)

  - x86: Display correct settings for the SPECTRE_V[12] bug
    (Kanth Ghatraju) [Orabug: 27376697] (CVE-2017-5715)
    (CVE-2017-5753)

  - x86/cpu: Implement CPU vulnerabilites sysfs functions
    (Thomas Gleixner) [Orabug: 27376697] (CVE-2017-5715)
    (CVE-2017-5753)

  - x86/IBRS/IBPB: Set sysctl_ibrs/ibpb_enabled properly
    (Boris Ostrovsky) [Orabug: 27376697] (CVE-2017-5715)

  - x86/spec_ctrl: Disable if running as Xen PV guest
    (Konrad Rzeszutek Wilk) [Orabug: 27376697]
    (CVE-2017-5715)

  - sysfs/cpu: Add vulnerability folder (Thomas Gleixner)
    [Orabug: 27376697] (CVE-2017-5715) (CVE-2017-5754)

  - x86, cpu: Expand cpufeature facility to include cpu bugs
    (Borislav Petkov) [Orabug: 27376697] (CVE-2017-5715)

  - x86/cpufeatures: Add X86_BUG_SPECTRE_V[12] (Kanth
    Ghatraju) [Orabug: 27376697] (CVE-2017-5715)

  - x86/cpufeatures: Add X86_BUG_CPU_MELTDOWN (Kanth
    Ghatraju) [Orabug: 27376697] (CVE-2017-5754)

  - x86/entry: STUFF_RSB only after switching to kernel CR3
    (Ankur Arora) [Orabug: 27376697] (CVE-2017-5715)

  - x86/entry: Stuff RSB for entry to kernel for non-SMEP
    platform (Tim Chen) [Orabug: 27376697] (CVE-2017-5715)

  - x86/IBRS: Make sure we restore MSR_IA32_SPEC_CTRL to a
    valid value (Boris Ostrovsky) [Orabug: 27376697]
    (CVE-2017-5715)

  - x86: Use IBRS for firmware update path (David Woodhouse)
    [Orabug: 27376697] (CVE-2017-5715)

  - x86/microcode: Recheck IBRS features on microcode reload
    (Tim Chen) [Orabug: 27376697] (CVE-2017-5715)

  - x86/idle: Disable IBRS entering idle and enable it on
    wakeup (Tim Chen) [Orabug: 27376697] (CVE-2017-5715)

  - x86/spec_ctrl: Add sysctl knobs to enable/disable
    SPEC_CTRL feature (Tim Chen) [Orabug: 27376697]
    (CVE-2017-5715)

  - x86/enter: Use IBRS on syscall and interrupts (Tim Chen)
    [Orabug: 27376697] (CVE-2017-5715)

  - x86/enter: MACROS to set/clear IBRS (Tim Chen) [Orabug:
    27376697] (CVE-2017-5715)

  - x86/feature: Detect the x86 IBRS feature to control
    Speculation (Tim Chen) [Orabug: 27376697]
    (CVE-2017-5715)

  - x86/pti/efi: broken conversion from efi to kernel page
    table (Pavel Tatashin) [Orabug: 27333764]
    (CVE-2017-5754)

  - PTI: unbreak EFI old_memmap (Jiri Kosina) [Orabug:
    27333764] [Orabug: 27333760] (CVE-2017-5754)
    (CVE-2017-5754)

  - kaiser: Set _PAGE_NX only if supported (Lepton Wu)
    [Orabug: 27333764] (CVE-2017-5754)

  - kaiser: rename X86_FEATURE_KAISER to X86_FEATURE_PTI
    (Mike Kravetz) [Orabug: 27333764] (CVE-2017-5754)

  - KPTI: Rename to PAGE_TABLE_ISOLATION (Kees Cook)
    [Orabug: 27333764] (CVE-2017-5754)

  - x86/kaiser: Check boottime cmdline params (Mike Kravetz)
    [Orabug: 27333764] (CVE-2017-5754)

  - kaiser: x86: Fix NMI handling (Jiri Kosina) [Orabug:
    27333764] (CVE-2017-5754)

  - kaiser: move paravirt clock vsyscall mapping out of
    kaiser_init (Mike Kravetz) [Orabug: 27333764]
    (CVE-2017-5754)

  - kaiser: disable if xen PARAVIRT (Mike Kravetz) [Orabug:
    27333764] (CVE-2017-5754)

  - x86/kaiser: Reenable PARAVIRT (Borislav Petkov) [Orabug:
    27333764] (CVE-2017-5754)

  - kaiser: kaiser_flush_tlb_on_return_to_user check PCID
    (Hugh Dickins) [Orabug: 27333764] (CVE-2017-5754)

  - kaiser: asm/tlbflush.h handle noPGE at lower level (Hugh
    Dickins) [Orabug: 27333764] (CVE-2017-5754)

  - kaiser: use ALTERNATIVE instead of x86_cr3_pcid_noflush
    (Hugh Dickins) [Orabug: 27333764] (CVE-2017-5754)

  - x86/kaiser: Rename and simplify X86_FEATURE_KAISER
    handling (Borislav Petkov) [Orabug: 27333764]
    (CVE-2017-5754)

  - kaiser: add 'nokaiser' boot option, using ALTERNATIVE
    (Hugh Dickins) [Orabug: 27333764] (CVE-2017-5754)

  - x86/alternatives: add asm ALTERNATIVE macro (Mike
    Kravetz) [Orabug: 27333764] (CVE-2017-5754)

  - kaiser: alloc_ldt_struct use get_zeroed_page (Hugh
    Dickins) [Orabug: 27333764] (CVE-2017-5754)

  - x86: kvmclock: Disable use from vDSO if KPTI is enabled
    (Ben Hutchings) [Orabug: 27333764] (CVE-2017-5754)

  - kaiser: Fix build with CONFIG_FUNCTION_GRAPH_TRACER
    (Kees Cook) [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm/kaiser: re-enable vsyscalls (Andrea Arcangeli)
    [Orabug: 27333764] (CVE-2017-5754)

  - KAISER: Kernel Address Isolation (Richard Fellner)
    [Orabug: 27333764] (CVE-2017-5754)

  - kprobes: Prohibit probing on .entry.text code (Masami
    Hiramatsu) [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm/64: Fix reboot interaction with CR4.PCIDE (Andy
    Lutomirski) [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: Enable CR4.PCIDE on supported systems (Andy
    Lutomirski) [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: Add the 'nopcid' boot option to turn off PCID
    (Andy Lutomirski) [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: Disable PCID on 32-bit kernels (Andy Lutomirski)
    [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: Remove the UP asm/tlbflush.h code, always use
    the (formerly) SMP code (Andy Lutomirski) [Orabug:
    27333764] (CVE-2017-5754)

  - x86/mm: Fix flush_tlb_page on Xen (Andy Lutomirski)
    [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: Disable preemption during CR3 read+write
    (Sebastian Andrzej Siewior) [Orabug: 27333764]
    (CVE-2017-5754)

  - sched/core: Idle_task_exit shouldn't use
    switch_mm_irqs_off (Andy Lutomirski) [Orabug: 27333764]
    (CVE-2017-5754)

  - x86/mm, sched/core: Turn off IRQs in switch_mm (Andy
    Lutomirski) [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm, sched/core: Uninline switch_mm (Andy Lutomirski)
    [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: Build arch/x86/mm/tlb.c even on !SMP (Andy
    Lutomirski) [Orabug: 27333764] (CVE-2017-5754)

  - sched/core: Add switch_mm_irqs_off and use it in the
    scheduler (Andy Lutomirski) [Orabug: 27333764]
    (CVE-2017-5754)

  - mm/mmu_context, sched/core: Fix mmu_context.h assumption
    (Ingo Molnar) [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: If INVPCID is available, use it to flush global
    mappings (Andy Lutomirski) [Orabug: 27333764]
    (CVE-2017-5754)

  - x86/mm: Add a 'noinvpcid' boot option to turn off
    INVPCID (Andy Lutomirski) [Orabug: 27333764]
    (CVE-2017-5754)

  - x86/mm: Fix INVPCID asm constraint (Borislav Petkov)
    [Orabug: 27333764] (CVE-2017-5754)

  - x86/mm: Add INVPCID helpers (Andy Lutomirski) [Orabug:
    27333764] (CVE-2017-5754)

  - x86: Clean up cr4 manipulation (Andy Lutomirski)
    [Orabug: 27333764] (CVE-2017-5754)

  - x86/paravirt: Don't patch flush_tlb_single (Thomas
    Gleixner) [Orabug: 27333764] (CVE-2017-5754)

  - x86/ldt: Make modify_ldt synchronous (Andy Lutomirski)
    [Orabug: 27333764] (CVE-2017-5754) (CVE-2015-5157)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-January/000827.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc71259c"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.20.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.20.2.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
