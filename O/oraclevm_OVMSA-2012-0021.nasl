#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2012-0021.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79477);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0744", "CVE-2012-0217", "CVE-2012-0218");
  script_bugtraq_id(53856, 53955);

  script_name(english:"OracleVM 3.1 : xen (OVMSA-2012-0021)");
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

  - x86-64: detect processors subject to AMD erratum #121
    and refuse to boot(CVE-2006-0744)

  - guest denial of service on syscall/sysenter exception
    generation (CVE-2012-0217),(CVE-2012-0218)

  - Remove unnecessary balloon retries on vm create. This is
    a backport from fix for bug 14143327."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2012-June/000082.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'FreeBSD Intel SYSRET Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "3\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.1", reference:"xen-4.1.2-18.el5.3")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-devel-4.1.2-18.el5.3")) flag++;
if (rpm_check(release:"OVS3.1", reference:"xen-tools-4.1.2-18.el5.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
