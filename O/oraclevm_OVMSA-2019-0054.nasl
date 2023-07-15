#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0054.
#

include("compat.inc");

if (description)
{
  script_id(131150);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2018-12207");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2019-0054)");
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
    commit=a3ec6768f487946b7316364bc9bd17ce4d752af5

  - BUILDINFO: QEMU upstream
    commit=8bff6989bd0bafcc0ddf859c23ce6a2ff21a80ff

  - BUILDINFO: QEMU traditional
    commit=346fdd7edd73f8287d0d0a2bab9c67b71bc6b8ba

  - BUILDINFO: IPXE
    commit=9a93db3f0947484e30e753bbd61a10b17336e20e

  - BUILDINFO: SeaBIOS
    commit=7d9cbe613694924921ed1a6f8947d711c5832eee

  - x86/vtx ept-shatter ... (Andrew Cooper) [Orabug:
    30522238] (CVE-2018-12207)

  - x86: rename public functions in p2m-pt.c (Mukesh Rathor)
    [Orabug: 30522238]

  - Rename 'set_p2m_entry' to 'p2m_set_entry' (Mukesh
    Rathor) [Orabug: 30522238]

  - x86/mm: add information about faulted page's presence to
    npfec structure (Boris Ostrovsky) [Orabug: 30522238]

  - relocate struct npfec definition into common (Tamas K
    Lengyel) 

  - EPT: utilize GLA->GPA translation known for certain
    faults (Jan Beulich) [Orabug: 30522238]

  - x86/mem_event: deliver gla fault EPT violation
    information (Tamas K Lengyel) [Orabug: 30522238]

  - x86: consolidate boolean inputs in hvm and p2m into a
    shared bitmap (Tamas K Lengyel) [Orabug: 30522238]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2019-November/000967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94d8eba2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_exists(rpm:"xen-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-155.0.75.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-155.0.75.el6")) flag++;

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
