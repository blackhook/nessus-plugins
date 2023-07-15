#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0021.
#

include("compat.inc");

if (description)
{
  script_id(107130);
  script_version("3.9");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-7540", "CVE-2018-7541");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2018-0021) (Meltdown) (Spectre)");
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
    commit=b2a6db11ced11291a472bc1bda20ce329eda4d66

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - gnttab: don't blindly free status pages upon version
    change (Andrew Cooper)&nbsp  [Orabug: 27571750]&nbsp 
    (CVE-2018-7541)

  - memory: don't implicitly unpin for decrease-reservation
    (Andrew Cooper)&nbsp  [Orabug: 27571737]&nbsp 
    (CVE-2018-7540)

  - BUILDINFO: xen
    commit=873b8236e886daa3c26dae28d0c1c53d88447dc0

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

  - BUILDINFO: xen
    commit=81602116e75b6bbc519366b242c71888aa1b1673

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
    [Orabug: 27553376]&nbsp  (CVE-2017-5753) (CVE-2017-5715)
    (CVE-2017-5754)

  - x86: allow easier disabling of BTI mitigations
    (Zhenzhong Duan) [Orabug: 27553376]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - x86/boot: Make alternative patching NMI-safe (Andrew
    Cooper) [Orabug: 27553376]&nbsp  (CVE-2017-5753)
    (CVE-2017-5715) (CVE-2017-5754)

  - xen/cmdline: Fix parse_boolean for unadorned values
    (Andrew Cooper)&nbsp  [Orabug: 27553376]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - Optimize the context switch code a bit (Zhenzhong
    Duan)&nbsp  [Orabug: 27553376]&nbsp  (CVE-2017-5753)
    (CVE-2017-5715) (CVE-2017-5754)

  - Update init_speculation_mitigations to upstream's
    (Zhenzhong Duan)&nbsp  [Orabug: 27553376]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - x86/entry: Avoid using alternatives in NMI/#MC paths
    (Andrew Cooper)&nbsp  [Orabug: 27553376]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - Update RSB related implementation to upstream ones
    (Zhenzhong Duan)&nbsp  [Orabug: 27553376]&nbsp 
    (CVE-2017-5753) (CVE-2017-5715) (CVE-2017-5754)

  - BUILDINFO: xen
    commit=c6a2fe8d72a3eba01b22cbe495e60cb6837fe8d0

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
    27445678]

  - BUILDINFO: xen
    commit=9657d91fcbf49798d2c5135866e1947113d536dc

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/Spectre: Set thunk to THUNK_NONE if compiler support
    is not available (Boris Ostrovsky)&nbsp  [Orabug:
    27375688]

  - BUILDINFO: xen
    commit=4e5826dfcb56d3a868a9934646989f8483f03b3c

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - xen: No dependencies on dracut and microcode_ctl RPMs
    (Boris Ostrovsky)&nbsp  [Orabug: 27409718]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-March/000832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de7c508d"
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
if (rpm_exists(rpm:"xen-4.4.4-105", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-105.0.36.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-105", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-105.0.36.el6")) flag++;

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
