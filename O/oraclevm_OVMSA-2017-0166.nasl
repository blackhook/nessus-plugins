#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0166.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104249);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15588", "CVE-2017-15589", "CVE-2017-15590", "CVE-2017-15592", "CVE-2017-15593", "CVE-2017-15594", "CVE-2017-15595", "CVE-2017-15597");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2017-0166)");
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
    commit=6c164f71ed0dc46201f1d69de65d05d138556fcc

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/cpu: fix IST handling during PCPU bringup (Andrew
    Cooper) [Orabug: 26901427] (CVE-2017-15594)

  - x86/shadow: Don't create self-linear shadow mappings for
    4-level translated guests (Andrew Cooper) [Orabug:
    26901416] (CVE-2017-15592)

  - x86: Disable the use of auto-translated PV guests
    (Andrew Cooper) [Orabug: 26901416] (CVE-2017-15592)

  - x86: don't allow page_unlock to drop the last type
    reference (Jan Beulich) [Orabug: 26901404]
    (CVE-2017-15593)

  - x86: don't store possibly stale TLB flush time stamp
    (Jan Beulich) [Orabug: 26901395] (CVE-2017-15588)

  - x86/mm: Disable PV linear pagetables by default (George
    Dunlap) [Orabug: 26901366] (CVE-2017-15595)

  - x86: limit linear page table use to a single level (Jan
    Beulich) [Orabug: 26901366] (CVE-2017-15595)

  - x86/HVM: prefill partially used variable on emulation
    paths (Jan Beulich) [Orabug: 26901350] (CVE-2017-15589)

  - x86/FLASK: fix unmap-domain-IRQ XSM hook (Jan Beulich)
    [Orabug: 26901322] (CVE-2017-15590)

  - x86/IRQ: conditionally preserve irq <-> pirq mapping on
    map error paths (Jan Beulich) [Orabug: 26901322]
    (CVE-2017-15590)

  - x86/MSI: disallow redundant enabling (Jan Beulich)
    [Orabug: 26901322] (CVE-2017-15590)

  - x86: enforce proper privilege when (un)mapping pIRQ-s
    (Jan Beulich) [Orabug: 26901322] (CVE-2017-15590)

  - x86: don't allow MSI pIRQ mapping on unowned device (Jan
    Beulich) [Orabug: 26901322] (CVE-2017-15590)

  - gnttab: fix pin count / page reference race (Jan
    Beulich) [Orabug: 26901282] (CVE-2017-15597)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-October/000797.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1553e768"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_exists(rpm:"xen-4.4.4-105", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-105.0.25.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-105", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-105.0.25.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
