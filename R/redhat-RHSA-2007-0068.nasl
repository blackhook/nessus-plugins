#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0068. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25315);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-5540", "CVE-2006-5541", "CVE-2006-5542", "CVE-2007-0555", "CVE-2007-0556");
  script_bugtraq_id(22387);
  script_xref(name:"RHSA", value:"2007:0068");

  script_name(english:"RHEL 5 : postgresql (RHSA-2007:0068)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

Two flaws were found in the way the PostgreSQL server handles certain
SQL-language functions. An authenticated user could execute a sequence
of commands which could crash the PostgreSQL server or possibly read
from arbitrary memory locations. A user would need to have permissions
to drop and add database tables to be able to exploit these issues
(CVE-2007-0555, CVE-2007-0556).

Several denial of service flaws were found in the PostgreSQL server.
An authenticated user could execute certain SQL commands which could
crash the PostgreSQL server (CVE-2006-5540, CVE-2006-5541,
CVE-2006-5542).

Users of PostgreSQL should upgrade to these updated packages
containing PostgreSQL version 8.1.8 which corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2007:0068"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0068";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-contrib-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-contrib-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-contrib-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-devel-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-docs-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-docs-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-docs-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"postgresql-libs-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-pl-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-pl-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-pl-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-python-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-python-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-python-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-server-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-server-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-server-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-tcl-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-tcl-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-tcl-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"postgresql-test-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"postgresql-test-8.1.8-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"postgresql-test-8.1.8-1.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
  }
}
