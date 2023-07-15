#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0007.
#

include('compat.inc');

if (description)
{
  script_id(105761);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"IAVA", value:"2018-A-0062-S");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0007) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - x86/ibrs: Remove 'ibrs_dump' and remove the pr_debug
    (Konrad Rzeszutek Wilk) [Orabug: 27350825]

  - kABI: Revert kABI: Make the boot_cpu_data look normal
    (Konrad Rzeszutek Wilk) (CVE-2017-5715)

  - userns: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - udf: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - net: mpls: prevent speculative execution (Elena
    Reshetova) [Orabug: 27340459] (CVE-2017-5753)

  - fs: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - ipv6: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - ipv4: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - Thermal/int340x: prevent speculative execution (Elena
    Reshetova) [Orabug: 27340459] (CVE-2017-5753)

  - cw1200: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - qla2xxx: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - p54: prevent speculative execution (Elena Reshetova)
    [Orabug: 27340459] (CVE-2017-5753)

  - carl9170: prevent speculative execution (Elena
    Reshetova) [Orabug: 27340459] (CVE-2017-5753)

  - uvcvideo: prevent speculative execution (Elena
    Reshetova) [Orabug: 27340459] (CVE-2017-5753)

  - bpf: prevent speculative execution in eBPF interpreter
    (Elena Reshetova) [Orabug: 27340459] (CVE-2017-5753)

  - locking/barriers: introduce new observable speculation
    barrier (Elena Reshetova) [Orabug: 27340459]
    (CVE-2017-5753)

  - x86/cpu/AMD: Remove now unused definition of
    MFENCE_RDTSC feature (Elena Reshetova) [Orabug:
    27340459] (CVE-2017-5753)

  - x86/cpu/AMD: Make the LFENCE instruction serialized
    (Elena Reshetova) [Orabug: 27340459] (CVE-2017-5753)

  - kABI: Make the boot_cpu_data look normal. (Konrad
    Rzeszutek Wilk) [Orabug: 27339995] (CVE-2017-5715)

  - kernel.spec: Require the new microcode_ctl. (Konrad
    Rzeszutek Wilk) [Orabug: 27339995] (CVE-2017-5715)
    (CVE-2017-5715)

  - x86/microcode/AMD: Add support for fam17h microcode
    loading (Tom Lendacky) [Orabug: 27339995]
    (CVE-2017-5715)

  - x86/spec_ctrl: Disable if running as Xen PV guest.
    (Konrad Rzeszutek Wilk) [Orabug: 27339995]
    (CVE-2017-5715)

  - Set IBPB when running a different VCPU (Dave Hansen)
    [Orabug: 27339995] (CVE-2017-5715)

  - Clear the host registers after setbe (Jun Nakajima)
    [Orabug: 27339995] (CVE-2017-5715)

  - Use the ibpb_inuse variable. (Jun Nakajima) [Orabug:
    27339995] (CVE-2017-5715)

  - KVM: x86: add SPEC_CTRL to MSR and CPUID lists (Andrea
    Arcangeli) [Orabug: 27339995] (CVE-2017-5715)

  - kvm: vmx: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD
    (Paolo Bonzini) [Orabug: 27339995] (CVE-2017-5715)

  - Use the 'ibrs_inuse' variable. (Jun Nakajima) [Orabug:
    27339995] (CVE-2017-5715)

  - kvm: svm: add MSR_IA32_SPEC_CTRL and MSR_IA32_PRED_CMD
    (Andrea Arcangeli) [Orabug: 27339995] (CVE-2017-5715)

  - x86/svm: Set IBPB when running a different VCPU (Paolo
    Bonzini) [Orabug: 27339995] (CVE-2017-5715)

  - x86/kvm: Pad RSB on VM transition (Tim Chen) [Orabug:
    27339995] (CVE-2017-5715)

  - x86/cpu/AMD: Add speculative control support for AMD
    (Tom Lendacky) [Orabug: 27339995] (CVE-2017-5715)

  - x86/microcode: Recheck IBRS and IBPB feature on
    microcode reload (Tim Chen) [Orabug: 27339995]
    (CVE-2017-5715)

  - x86: Move IBRS/IBPB feature detection to scattered.c
    (Tim Chen) [Orabug: 27339995] (CVE-2017-5715)

  - x86/spec_ctrl: Add lock to serialize changes to ibrs and
    ibpb control (Tim Chen) [Orabug: 27339995]
    (CVE-2017-5715)

  - x86/spec_ctrl: Add sysctl knobs to enable/disable
    SPEC_CTRL feature (Konrad Rzeszutek Wilk) [Orabug:
    27339995] (CVE-2017-5715)

  - x86/kvm: clear registers on VM exit (Tom Lendacky)
    [Orabug: 27339995] (CVE-2017-5715)

  - x86/kvm: Set IBPB when switching VM (Tim Chen) [Orabug:
    27339995] (CVE-2017-5715)

  - *INCOMPLETE* x86/syscall: Clear unused extra registers
    on syscall entrance (Konrad Rzeszutek Wilk) [Orabug:
    27339995] (CVE-2017-5715)

  - x86/entry: Stuff RSB for entry to kernel for non-SMEP
    platform (Konrad Rzeszutek Wilk) [Orabug: 27339995]
    (CVE-2017-5715)

  - x86/mm: Only set IBPB when the new thread cannot ptrace
    current thread (Konrad Rzeszutek Wilk) [Orabug:
    27339995] (CVE-2017-5715)

  - x86/mm: Set IBPB upon context switch (Tim Chen) [Orabug:
    27339995] (CVE-2017-5715)

  - x86/idle: Disable IBRS when offlining cpu and re-enable
    on wakeup (Tim Chen) [Orabug: 27339995] (CVE-2017-5715)

  - x86/idle: Disable IBRS entering idle and enable it on
    wakeup (Tim Chen) [Orabug: 27339995] (CVE-2017-5715)

  - x86/spec_ctrl: save IBRS MSR value in paranoid_entry
    (Andrea Arcangeli) [Orabug: 27339995] (CVE-2017-5715)

  - *Scaffolding* x86/spec_ctrl: Add sysctl knobs to
    enable/disable SPEC_CTRL feature (Tim Chen) [Orabug:
    27339995] (CVE-2017-5715)

  - x86/enter: Use IBRS on syscall and interrupts (Tim Chen)
    [Orabug: 27339995] (CVE-2017-5715)

  - x86: Add macro that does not save rax, rcx, rdx on stack
    to disable IBRS (Tim Chen) [Orabug: 27339995]
    (CVE-2017-5715)

  - x86/enter: MACROS to set/clear IBRS and set IBP (Tim
    Chen) [Orabug: 27339995] (CVE-2017-5715)

  - x86/feature: Report presence of IBPB and IBRS control
    (Tim Chen) [Orabug: 27339995] (CVE-2017-5715)

  - x86: Add STIBP feature enumeration (Konrad Rzeszutek
    Wilk) [Orabug: 27339995] (CVE-2017-5715)

  - x86/cpufeature: Add X86_FEATURE_IA32_ARCH_CAPS and
    X86_FEATURE_IBRS_ATT (Konrad Rzeszutek Wilk) [Orabug:
    27339995] (CVE-2017-5715)

  - x86/feature: Enable the x86 feature to control (Tim
    Chen) [Orabug: 27339995] (CVE-2017-5715)");
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-January/000818.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e046af99");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek / kernel-uek-firmware packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-112.14.5.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-112.14.5.el6uek")) flag++;

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
