#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0088.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79525);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4494", "CVE-2013-4553", "CVE-2013-4554");
  script_bugtraq_id(63494, 63931, 63933);

  script_name(english:"OracleVM 2.2 : xen (OVMSA-2013-0088)");
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

  - x86/HVM: only allow ring 0 guest code to make hypercalls
    XSA-76 (Jan Beulich) [17822325] (CVE-2013-4554)

  - x86: restrict XEN_DOMCTL_getmemlist XSA-74 (Jan Beulich)
    [17821907] (CVE-2013-4553)

  - gnttab: correct locking order reversal XSA-73 (Andrew
    Cooper) [orabug 17768955] (CVE-2013-4494)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-December/000198.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9046329"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-pvhvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/06");
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
if (! preg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"xen-3.4.0-0.2.15.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-64-3.4.0-0.2.15.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-debugger-3.4.0-0.2.15.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-devel-3.4.0-0.2.15.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-pvhvm-devel-3.4.0-0.2.15.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-tools-3.4.0-0.2.15.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-64 / xen-debugger / xen-devel / xen-pvhvm-devel / etc");
}
