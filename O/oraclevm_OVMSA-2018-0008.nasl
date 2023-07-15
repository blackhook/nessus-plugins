#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0008.
#

include("compat.inc");

if (description)
{
  script_id(105762);
  script_version("3.7");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-5715", "CVE-2017-5754");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0008) (Meltdown) (Spectre)");
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

  - x86/ia32: save and clear registers on syscall. (Jamie
    Iles) [Orabug: 27355759] (CVE-2017-5754)

  - x86/IBRS: Save current status of MSR_IA32_SPEC_CTRL
    (Boris Ostrovsky) 

  - pti: Rename X86_FEATURE_KAISER to X86_FEATURE_PTI (Pavel
    Tatashin) [Orabug: 27352353] (CVE-2017-5754)

  - usb/core: usb_alloc_dev: fix setting of ->portnum
    (Nicolai Stange) 

  - x86/spec_ctrl: Add missing IBRS_DISABLE (Konrad
    Rzeszutek Wilk)

  - Make use of ibrs_inuse consistent. (Jun Nakajima)

  - x86/kvm: Set IBRS on VMEXIT if guest disabled it.
    (Konrad Rzeszutek Wilk)

  - Re-introduce clearing of r12-15, rbp, rbx (Kris Van
    Hees) [Orabug: 27352353] (CVE-2017-5754)

  - x86: more ibrs/pti fixes (Pavel Tatashin) [Orabug:
    27352353] (CVE-2017-5754)

  - x86/spec: Actually do the check for in_use on
    ENABLE_IBRS (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - kvm: svm: Expose the CPUID.0x80000008 ebx flag. (Konrad
    Rzeszutek Wilk) (CVE-2017-5715)

  - x86/spec_ctrl: Provide the sysfs version of the
    ibrs_enabled (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - x86: Use better #define for FEATURE_ENABLE_IBRS and 0
    (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - x86: Instead of 0x2, 0x4, and 0x1 use #defines. (Konrad
    Rzeszutek Wilk) (CVE-2017-5715)

  - kpti: Disable when running under Xen PV (Konrad
    Rzeszutek Wilk) [Orabug: 27352353] (CVE-2017-5754)

  - x86: Don't ENABLE_IBRS in nmi when we are still running
    on user cr3 (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - x86/enter: Use IBRS on syscall and interrupts - fix ia32
    path (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - x86: Fix spectre/kpti integration (Konrad Rzeszutek
    Wilk) [Orabug: 27352353] (CVE-2017-5754)

  - PTI: unbreak EFI old_memmap (Jiri Kosina) [Orabug:
    27352353] (CVE-2017-5754)

  - KAISER KABI tweaks. (Martin K. Petersen) [Orabug:
    27352353] (CVE-2017-5754)

  - x86/ldt: fix crash in ldt freeing. (Jamie Iles) [Orabug:
    27352353] (CVE-2017-5754)

  - x86/entry: Define 'cpu_current_top_of_stack' for 64-bit
    code (Denys Vlasenko) [Orabug: 27352353] (CVE-2017-5754)

  - x86/entry: Remove unused 'kernel_stack' per-cpu variable
    (Denys Vlasenko) [Orabug: 27352353] (CVE-2017-5754)

  - x86/entry: Stop using PER_CPU_VAR(kernel_stack) (Denys
    Vlasenko) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: Set _PAGE_NX only if supported (Guenter Roeck)
    [Orabug: 27352353] (CVE-2017-5754)

  - x86/vdso: Get pvclock data from the vvar VMA instead of
    the fixmap (Andy Lutomirski) [Orabug: 27352353]
    (CVE-2017-5754)

  - KPTI: Report when enabled (Kees Cook) [Orabug: 27352353]
    (CVE-2017-5754)

  - KPTI: Rename to PAGE_TABLE_ISOLATION (Kees Cook)
    [Orabug: 27352353] (CVE-2017-5754)

  - x86/kaiser: Move feature detection up (Borislav Petkov)
    [Orabug: 27352353] (CVE-2017-5754)

  - x86/kaiser: Reenable PARAVIRT (Borislav Petkov) [Orabug:
    27352353] (CVE-2017-5754)

  - x86/paravirt: Don't patch flush_tlb_single (Thomas
    Gleixner) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: kaiser_flush_tlb_on_return_to_user check PCID
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: asm/tlbflush.h handle noPGE at lower level (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: drop is_atomic arg to kaiser_pagetable_walk
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: use ALTERNATIVE instead of x86_cr3_pcid_noflush
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - x86/kaiser: Check boottime cmdline params (Borislav
    Petkov) [Orabug: 27352353] (CVE-2017-5754)

  - x86/kaiser: Rename and simplify X86_FEATURE_KAISER
    handling (Borislav Petkov) [Orabug: 27352353]
    (CVE-2017-5754)

  - kaiser: add 'nokaiser' boot option, using ALTERNATIVE
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: fix unlikely error in alloc_ldt_struct (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: _pgd_alloc without __GFP_REPEAT to avoid stalls
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: paranoid_entry pass cr3 need to paranoid_exit
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: x86_cr3_pcid_noflush and x86_cr3_pcid_user (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: PCID 0 for kernel and 128 for user (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: load_new_mm_cr3 let SWITCH_USER_CR3 flush user
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: enhanced by kernel and user PCIDs (Dave Hansen)
    [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: vmstat show NR_KAISERTABLE as nr_overhead (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: delete KAISER_REAL_SWITCH option (Hugh Dickins)
    [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: name that 0x1000 KAISER_SHADOW_PGD_OFFSET (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: cleanups while trying for gold link (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: kaiser_remove_mapping move along the pgd (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: tidied up kaiser_add/remove_mapping slightly
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: tidied up asm/kaiser.h somewhat (Hugh Dickins)
    [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: ENOMEM if kaiser_pagetable_walk NULL (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: fix perf crashes (Hugh Dickins) [Orabug:
    27352353] (CVE-2017-5754)

  - kaiser: fix regs to do_nmi ifndef CONFIG_KAISER (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: KAISER depends on SMP (Hugh Dickins) [Orabug:
    27352353] (CVE-2017-5754)

  - kaiser: fix build and FIXME in alloc_ldt_struct (Hugh
    Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: stack map PAGE_SIZE at THREAD_SIZE-PAGE_SIZE
    (Hugh Dickins) [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: do not set _PAGE_NX on pgd_none (Hugh Dickins)
    [Orabug: 27352353] (CVE-2017-5754)

  - kaiser: merged update (Dave Hansen) [Orabug: 27352353]
    (CVE-2017-5754)

  - KAISER: Kernel Address Isolation (Richard Fellner)
    [Orabug: 27352353] (CVE-2017-5754)

  - x86/boot: Add early cmdline parsing for options with
    arguments (Tom Lendacky) [Orabug: 27352353]
    (CVE-2017-5754)

  - x86/mm/64: Fix reboot interaction with CR4.PCIDE (Andy
    Lutomirski) [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: Enable CR4.PCIDE on supported systems (Andy
    Lutomirski) [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: Add the 'nopcid' boot option to turn off PCID
    (Andy Lutomirski) [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: Disable PCID on 32-bit kernels (Andy Lutomirski)
    [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: Remove the UP asm/tlbflush.h code, always use
    the (formerly) SMP code (Andy Lutomirski) [Orabug:
    27352353] (CVE-2017-5754)

  - x86/mm: Reimplement flush_tlb_page using
    flush_tlb_mm_range (Andy Lutomirski) [Orabug: 27352353]
    (CVE-2017-5754)

  - x86/mm: Make flush_tlb_mm_range more predictable (Andy
    Lutomirski) [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: Remove flush_tlb and flush_tlb_current_task
    (Andy Lutomirski) [Orabug: 27352353] (CVE-2017-5754)

  - x86/vm86/32: Switch to flush_tlb_mm_range in
    mark_screen_rdonly (Andy Lutomirski) [Orabug: 27352353]
    (CVE-2017-5754)

  - x86/irq: Do not substract irq_tlb_count from
    irq_call_count (Aaron Lu) [Orabug: 27352353]
    (CVE-2017-5754)

  - sched/core: Idle_task_exit shouldn't use
    switch_mm_irqs_off (Andy Lutomirski) [Orabug: 27352353]
    (CVE-2017-5754)

  - ARM: Hide finish_arch_post_lock_switch from modules
    (Steven Rostedt) [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm, sched/core: Turn off IRQs in switch_mm (Andy
    Lutomirski) [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm, sched/core: Uninline switch_mm (Andy Lutomirski)
    [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: Build arch/x86/mm/tlb.c even on !SMP (Andy
    Lutomirski) [Orabug: 27352353] (CVE-2017-5754)

  - sched/core: Add switch_mm_irqs_off and use it in the
    scheduler (Andy Lutomirski) [Orabug: 27352353]
    (CVE-2017-5754)

  - mm/mmu_context, sched/core: Fix mmu_context.h assumption
    (Ingo Molnar) [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: If INVPCID is available, use it to flush global
    mappings (Andy Lutomirski) [Orabug: 27352353]
    (CVE-2017-5754)

  - x86/mm: Add a 'noinvpcid' boot option to turn off
    INVPCID (Andy Lutomirski) [Orabug: 27352353]
    (CVE-2017-5754)

  - x86/mm: Fix INVPCID asm constraint (Borislav Petkov)
    [Orabug: 27352353] (CVE-2017-5754)

  - x86/mm: Add INVPCID helpers (Andy Lutomirski) [Orabug:
    27352353] (CVE-2017-5754)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-January/000819.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d39633bb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-112.14.10.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-112.14.10.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
