#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0002.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79494);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5634");
  script_bugtraq_id(57223);

  script_name(english:"OracleVM 3.0 : xen (OVMSA-2013-0002)");
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

  - VT-d: fix interrupt remapping source validation for
    devices behind legacy bridges Using SVT_VERIFY_BUS here
    doesn't make sense  native Linux also uses
    SVT_VERIFY_SID_SQ here instead. (CVE-2012-5634)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-January/000120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba9b9da1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
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
if (! preg(pattern:"^OVS" + "3\.0" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.0", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.0", reference:"xen-4.0.0-81.el5.26")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-devel-4.0.0-81.el5.26")) flag++;
if (rpm_check(release:"OVS3.0", reference:"xen-tools-4.0.0-81.el5.26")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
