#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0246.
#

include("compat.inc");

if (description)
{
  script_id(111772);
  script_version("1.5");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2018-3620", "CVE-2018-3646");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2018-0246) (Foreshadow)");
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
    commit=02cec92b3eb1612e37616b10400d82f1e3d8de85

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - l1tf: Utility to offline/online SMT siblings. (Ross
    Philipson) [Orabug: 28487050] (CVE-2018-3646)

  - x86/spec-ctrl: Introduce an option to control L1D_FLUSH
    for HVM guests (Andrew Cooper) [Orabug: 28487050]
    (CVE-2018-3620) (CVE-2018-3646)

  - x86/msr: Virtualise MSR_FLUSH_CMD for guests (Andrew
    Cooper) [Orabug: 28487050] (CVE-2018-3646)
    (CVE-2018-3646)

  - x86/spec-ctrl: CPUID/MSR definitions for L1D_FLUSH
    (Andrew Cooper) [Orabug: 28487050] (CVE-2018-3646)
    (CVE-2018-3646)

  - x86/spec-ctrl: Calculate safe PTE addresses for L1TF
    mitigations (Andrew Cooper) [Orabug: 28487050]
    (CVE-2018-3620) (CVE-2018-3646)

  - x86: command line option to avoid use of secondary
    hyper-threads (Jan Beulich) [Orabug: 28487050]
    (CVE-2018-3646)

  - cpupools: fix state when downing a CPU failed (Jan
    Beulich) [Orabug: 28487050] (CVE-2018-3646)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-August/000882.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3f57f0d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_exists(rpm:"xen-4.4.4-196", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-196.0.2.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-196", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-196.0.2.el6")) flag++;

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
