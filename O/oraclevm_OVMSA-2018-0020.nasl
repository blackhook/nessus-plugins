#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0020.
#

include("compat.inc");

if (description)
{
  script_id(107129);
  script_version("3.9");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-7540", "CVE-2018-7541");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2018-0020) (Meltdown) (Spectre)");
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

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=9ccc143584e12027a8db854d19ce8a120d22cfac

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - gnttab: don't blindly free status pages upon version
    change (Andrew Cooper)&nbsp  [Orabug: 27614581]&nbsp 
    (CVE-2018-7541)

  - memory: don't implicitly unpin for decrease-reservation
    (Andrew Cooper)&nbsp  [Orabug: 27614605]&nbsp 
    (CVE-2018-7540)

  - xend: allow setting topology if smt is off in bios
    (Elena Ufimtseva)&nbsp  

  - x86/svm: clear CPUID IBPB when feature is not supported
    (Elena Ufimtseva)&nbsp  [Orabug: 27416699]

  - x86/domain: Move hvm_vcpu_initialize before
    cpuid_policy_changed (Elena Ufimtseva)&nbsp  [Orabug:
    27416699]

  - x86, amd_ucode: support multiple container files
    appended together (Aravind Gopalakrishnan)&nbsp 
    [Orabug: 27416699]

  - x86/intel: change default governor to performance (Joao
    Martins) 

  - x86/cpuidle: Disable deep C-states due to erratum AAJ72
    (Joao Martins)&nbsp  [Orabug: 27614625]

  - Revert 'set max cstate to 1' (Joao Martins)&nbsp 
    [Orabug: 27614625]

  - x86/cpuidle: add new CPU families (Jan Beulich)&nbsp 
    [Orabug: 27614625]

  - x86/Intel: Broadwell doesn't have
    PKG_C[8,9,10]_RESIDENCY MSRs (Jan Beulich)&nbsp 
    [Orabug: 27614625]

  - x86: support newer Intel CPU models (Jan Beulich)&nbsp 
    [Orabug: 27614625]

  - mwait-idle: add KBL support (Len Brown)&nbsp  [Orabug:
    27614625]

  - mwait-idle: add SKX support (Len Brown)&nbsp  [Orabug:
    27614625]

  - mwait_idle: Skylake Client Support (Len Brown)&nbsp 
    [Orabug: 27614625]

  - x86: support newer Intel CPU models (Jan Beulich)&nbsp 
    [Orabug: 27614625]

  - x86/idle: update to include further package/core
    residency MSRs (Jan Beulich)&nbsp  [Orabug: 27614625]

  - mwait-idle: support additional Broadwell model (Len
    Brown) [Orabug: 27614625]

  - x86/mwait-idle: Broadwell support (Len Brown)&nbsp 
    [Orabug: 27614625]

  - x86/mwait-idle: disable Baytrail Core and Module C6
    auto-demotion (Len Brown)&nbsp  [Orabug: 27614625]

  - mwait-idle: add CPU model 54 (Atom N2000 series) (Jan
    Kiszka) [Orabug: 27614625]

  - mwait-idle: support Bay Trail (Len Brown)&nbsp  [Orabug:
    27614625]

  - mwait-idle: allow sparse sub-state numbering, for Bay
    Trail (Len Brown)&nbsp  [Orabug: 27614625]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=c837c35e1c04791a50f930926ba815ca5b4d3661

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xend: restore smt parameter on guest reboot (Elena
    Ufimtseva) [Orabug: 27574191]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=f36f7903ae0886ab4ef7e3e01c83c9dba819537b

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/spec_ctrl: Fix several bugs in
    SPEC_CTRL_ENTRY_FROM_INTR_IST (Andrew Cooper)&nbsp 
    [Orabug: 27553369]&nbsp  (CVE-2017-5753) (CVE-2017-5715)
    (CVE-2017-5754)

  - x86: allow easier disabling of BTI mitigations
    (Zhenzhong Duan) [Orabug: 27553369]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - x86/boot: Make alternative patching NMI-safe (Andrew
    Cooper) [Orabug: 27553369]&nbsp  (CVE-2017-5753)
    (CVE-2017-5715) (CVE-2017-5754)

  - xen/cmdline: Fix parse_boolean for unadorned values
    (Andrew Cooper)&nbsp  [Orabug: 27553369]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - Optimize the context switch code a bit (Zhenzhong
    Duan)&nbsp  [Orabug: 27553369]&nbsp  (CVE-2017-5753)
    (CVE-2017-5715) (CVE-2017-5754)

  - Update init_speculation_mitigations to upstream's
    (Zhenzhong Duan)&nbsp  [Orabug: 27553369]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - x86/entry: Avoid using alternatives in NMI/#MC paths
    (Andrew Cooper)&nbsp  [Orabug: 27553369]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - Update RSB related implementation to upstream ones
    (Zhenzhong Duan)&nbsp  [Orabug: 27553369]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=bdecffda647e17f8aaeb4057bd1064236075bc9c

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xend: if secure boot is enabled don't write pci config
    space (Elena Ufimtseva)&nbsp  [Orabug: 27533309]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=46aa4f995b266e9dc0bce98b448423c5fdc79fde

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - hvmloader: Correct nr_vnodes when init_vnuma_info fails
    (Annie Li)&nbsp  

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=1fb819ca1b801af1f59983f34776501336a57979

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - Fail migration if destination does not allow pv guest
    running (Annie Li)&nbsp  [Orabug: 27465310]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=dfc241a5b6a952bde385b1d68ef42acf8f80302c

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86: Expose CPUID.7, EDX.26->27 and CPUID.0x80000008,
    EBX.12 (redux) (Konrad Rzeszutek Wilk)&nbsp  [Orabug:
    27445667]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=d5afa57c42732dc35a572582099c67ee3c397434

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - Enable creating pv guest on OVM3.4.4 by default (Annie
    Li) [Orabug: 27424482]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=619dd3aa6aac97dbc9f23fdae3d6fd6dfab8a0da

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xen/x86: Make sure identify_cpu is called with traps
    enabled (Joao Martins)&nbsp  [Orabug: 27393237]

  - xend: disallow pv guests to run (Joao Martins)&nbsp 
    [Orabug: 27370330]

  - hvmloader, x86/hvm, domctl: enumerate apicid based on
    vcpu_to_vnode (Joao Martins)&nbsp  [Orabug: 27119689]

  - xend: conditionally use dom0 vcpus for vnuma auto (Joao
    Martins) 

  - x86/Spectre: Set thunk to THUNK_NONE if compiler support
    is not available (Boris Ostrovsky)&nbsp  [Orabug:
    27375704]

  - BUILDINFO: OVMF
    commit=173bf5c847e3ca8b42c11796ce048d8e2e916ff8

  - BUILDINFO: xen
    commit=1d2270f50ef2b1b22b8f6ee7a9b571ea96f7f37b

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xen: No dependencies on dracut and microcode_ctl RPMs
    (Boris Ostrovsky)&nbsp  [Orabug: 27409734]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-March/000831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?884f76d4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/05");
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
if (rpm_exists(rpm:"xen-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-155.0.22.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-155.0.22.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
