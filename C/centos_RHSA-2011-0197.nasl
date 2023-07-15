#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0197 and 
# CentOS Errata and Security Advisory 2011:0197 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51888);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-4015");
  script_bugtraq_id(46084);
  script_xref(name:"RHSA", value:"2011:0197");

  script_name(english:"CentOS 4 / 5 : postgresql (CESA-2011:0197)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

A stack-based buffer overflow flaw was found in the way PostgreSQL
processed certain tokens from a SQL query when the intarray module was
enabled on a particular database. An authenticated database user
running a specially crafted SQL query could use this flaw to cause a
temporary denial of service (postgres daemon crash) or, potentially,
execute arbitrary code with the privileges of the database server.
(CVE-2010-4015)

Red Hat would like to thank Geoff Keating of the Apple Product
Security team for reporting this issue.

For Red Hat Enterprise Linux 4, the updated postgresql packages
contain a backported patch for this issue; there are no other changes.

For Red Hat Enterprise Linux 5, the updated postgresql packages
upgrade PostgreSQL to version 8.1.23, and contain a backported patch
for this issue. Refer to the PostgreSQL Release Notes for a full list
of changes :

http://www.postgresql.org/docs/8.1/static/release.html

For Red Hat Enterprise Linux 6, the updated postgresql packages
upgrade PostgreSQL to version 8.4.7, which includes a fix for this
issue. Refer to the PostgreSQL Release Notes for a full list of
changes :

http://www.postgresql.org/docs/8.4/static/release.html

All PostgreSQL users are advised to upgrade to these updated packages,
which correct this issue. If the postgresql service is running, it
will be automatically restarted after installing this update."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017381.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0ecc32f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017382.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ffa6e58"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-February/017253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64e32ff2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-February/017254.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc0eb446"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-contrib-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-contrib-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-devel-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-devel-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-docs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-docs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-jdbc-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-jdbc-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-libs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-libs-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-pl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-pl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-python-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-python-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-server-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-server-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-tcl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-tcl-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postgresql-test-7.4.30-1.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postgresql-test-7.4.30-1.el4_8.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postgresql-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-contrib-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-devel-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-docs-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-libs-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-pl-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-python-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-server-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-tcl-8.1.23-1.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-test-8.1.23-1.el5_6.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
