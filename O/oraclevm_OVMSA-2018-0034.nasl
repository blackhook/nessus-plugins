#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0034.
#

include("compat.inc");

if (description)
{
  script_id(109157);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2018-7750");

  script_name(english:"OracleVM 3.3 / 3.4 : python-paramiko (OVMSA-2018-0034)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Fix and enable tests (%check).

  - Backport a change which makes tests exit with nonzero
    status when they fail.

  - Add a fix for upstream tests for CVE-2018-7750 (broken
    in previous).

  - Fix a security flaw (CVE-2018-7750) in Paramiko's server
    mode (emphasis on **server** mode  this does **not**
    impact *client* use!) Backported from 1.10: Resolves
    #1557140"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-April/000844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?667e3b7a"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-April/000843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc3cf500"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-paramiko package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:python-paramiko");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/19");
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
if (! preg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"python-paramiko-1.7.5-4.el6_9")) flag++;

if (rpm_check(release:"OVS3.4", reference:"python-paramiko-1.7.5-4.el6_9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-paramiko");
}
