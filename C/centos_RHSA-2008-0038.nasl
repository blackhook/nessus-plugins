#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0038 and 
# CentOS Errata and Security Advisory 2008:0038 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29933);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_bugtraq_id(27163);
  script_xref(name:"RHSA", value:"2008:0038");

  script_name(english:"CentOS 4 / 5 : postgresql (CESA-2008:0038)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS). The postgresql packages include the client programs and
libraries needed to access a PostgreSQL DBMS server.

Will Drewry discovered multiple flaws in PostgreSQL's regular
expression engine. An authenticated attacker could use these flaws to
cause a denial of service by causing the PostgreSQL server to crash,
enter an infinite loop, or use extensive CPU and memory resources
while processing queries containing specially crafted regular
expressions. Applications that accept regular expressions from
untrusted sources may expose this problem to unauthorized attackers.
(CVE-2007-4769, CVE-2007-4772, CVE-2007-6067)

A privilege escalation flaw was discovered in PostgreSQL. An
authenticated attacker could create an index function that would be
executed with administrator privileges during database maintenance
tasks, such as database vacuuming. (CVE-2007-6600)

A privilege escalation flaw was discovered in PostgreSQL's Database
Link library (dblink). An authenticated attacker could use dblink to
possibly escalate privileges on systems with 'trust' or 'ident'
authentication configured. Please note that dblink functionality is
not enabled by default, and can only by enabled by a database
administrator on systems with the postgresql-contrib package
installed. (CVE-2007-3278, CVE-2007-6601)

All postgresql users should upgrade to these updated packages, which
include PostgreSQL 7.4.19 and 8.1.11, and resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014576.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f914e1bf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1dacf99"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0a224b2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014603.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ab22b25"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9cb288c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-contrib-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-contrib-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-contrib-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-devel-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-devel-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-devel-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-docs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-docs-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-docs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-jdbc-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-jdbc-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-libs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-libs-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-libs-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-pl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-pl-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-pl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-python-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-python-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-python-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-server-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-server-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-server-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-tcl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-tcl-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-tcl-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-test-7.4.19-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-test-7.4.19-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-test-7.4.19-1.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postgresql-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-contrib-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-devel-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-docs-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-libs-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-pl-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-python-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-server-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-tcl-8.1.11-1.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-test-8.1.11-1.el5_1.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
