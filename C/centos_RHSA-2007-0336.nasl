#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0336 and 
# CentOS Errata and Security Advisory 2007:0336 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25175);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2138");
  script_xref(name:"RHSA", value:"2007:0336");

  script_name(english:"CentOS 3 / 4 / 5 : postgresql (CESA-2007:0336)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

A flaw was found in the way PostgreSQL allows authenticated users to
execute security-definer functions. It was possible for an
unprivileged user to execute arbitrary code with the privileges of the
security-definer function. (CVE-2007-2138)

Users of PostgreSQL should upgrade to these updated packages
containing PostgreSQL version 8.1.9, 7.4.17, and 7.3.19 which corrects
this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f2cd560"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5274eeb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd0e5a82"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f737f86"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013741.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6476e452"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013744.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71d9906b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-contrib-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-devel-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-docs-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-jdbc-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-libs-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-pl-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-python-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-server-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-tcl-7.3.19-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-test-7.3.19-1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-contrib-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-devel-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-docs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-jdbc-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-libs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-pl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-python-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-server-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-tcl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"postgresql-test-7.4.17-1.RHEL4.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postgresql-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-contrib-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-debuginfo-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-devel-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-docs-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-libs-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-pl-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-python-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-server-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-tcl-8.1.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postgresql-test-8.1.9-1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
}
