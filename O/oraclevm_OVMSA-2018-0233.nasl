#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0233.
#

include("compat.inc");

if (description)
{
  script_id(110792);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639", "CVE-2018-3665");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2018-0233) (Spectre)");
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

  - BUILDINFO: xen
    commit=67e64eec4bfe342ca6c2ff0858ae7f5c39041013

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/HVM: Restart ioreq processing state machine (Boris
    Ostrovsky) 

  - BUILDINFO: xen
    commit=7e4f43226d60a48df300b32ce60ecff75ce2612d

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - svm: fix incorrect TSC scaling (Haozhong Zhang) [Orabug:
    28189188]

  - BUILDINFO: xen
    commit=ba8e4ae04e3594470f9ce1663135fbe8c25106af

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/spec-ctrl: Mitigations for LazyFPU (Ross Philipson)
    [Orabug: 28135217] (CVE-2018-3665)

  - x86: Support fully eager FPU context switching (Andrew
    Cooper) [Orabug: 28135217] (CVE-2018-3665)

  - BUILDINFO: xen
    commit=312880584fe084de632a6667254a5cc1c846179e

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - [xenmicrocode] Fix error reporting on successful return
    from tool (Ross Philipson) [Orabug: 28128506]

  - x86: correct default_xen_spec_ctrl calculation (Jan
    Beulich) [Orabug: 28034172]

  - x86/msr: Virtualise MSR_SPEC_CTRL.SSBD for guests to use
    (Andrew Cooper) [Orabug: 28034172] (CVE-2018-3639)

  - x86/Intel: Mitigations for GPZ SP4 - Speculative Store
    Bypass (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/AMD: Mitigations for GPZ SP4 - Speculative Store
    Bypass (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Introduce a new `spec-ctrl=` command line
    argument to replace `bti=` (Andrew Cooper) [Orabug:
    28034172] (CVE-2018-3639)

  - x86/cpuid: Improvements to guest policies for
    speculative sidechannel features (Andrew Cooper)
    [Orabug: 28034172] (CVE-2018-3639)

  - x86/spec_ctrl: Explicitly set Xen's default
    MSR_SPEC_CTRL value (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Split X86_FEATURE_SC_MSR into PV and HVM
    variants (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Elide MSR_SPEC_CTRL handling in idle
    context when possible (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Rename bits of infrastructure to avoid
    NATIVE and VMEXIT (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Fold the XEN_IBRS_[SET,CLEAR]
    ALTERNATIVES together (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Merge bti_ist_info and
    use_shadow_spec_ctrl into spec_ctrl_flags (Andrew
    Cooper) [Orabug: 28034172] (CVE-2018-3639)

  - x86/spec_ctrl: Express Xen's choice of MSR_SPEC_CTRL
    value as a variable (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Read MSR_ARCH_CAPABILITIES only once
    (Andrew Cooper) [Orabug: 28034172] (CVE-2018-3639)

  - x86/spec_ctrl: Assume that STIBP feature is always
    available (Boris Ostrovsky) [Orabug: 28034172]
    (CVE-2018-3639)

  - x86/spec_ctrl: Updates to retpoline-safety decision
    making (Andrew Cooper) [Orabug: 28034172]
    (CVE-2018-3639)

  - BUILDINFO: xen
    commit=dc770041d983843c860c06d405054c0e01a4fd98

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - one-off build"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-June/000869.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(rpm:"xen-4.4.4-105", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-105.0.50.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-105", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-105.0.50.el6")) flag++;

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
