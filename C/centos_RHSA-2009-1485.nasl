#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1485 and 
# CentOS Errata and Security Advisory 2009:1485 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42059);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-6600", "CVE-2009-3230");
  script_bugtraq_id(36314);
  script_xref(name:"RHSA", value:"2009:1485");

  script_name(english:"CentOS 3 : postgresql (CESA-2009:1485)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix a security issue are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced object-relational database management system
(DBMS).

It was discovered that the upstream patch for CVE-2007-6600 included
in the Red Hat Security Advisory RHSA-2008:0039 did not include
protection against misuse of the RESET ROLE and RESET SESSION
AUTHORIZATION commands. An authenticated user could use this flaw to
install malicious code that would later execute with superuser
privileges. (CVE-2009-3230)

All PostgreSQL users should upgrade to these updated packages, which
contain a backported patch to correct this issue. If you are running a
PostgreSQL server, the postgresql service must be restarted for this
update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53121e39"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016180.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d45da8c2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-contrib-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-contrib-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-devel-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-devel-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-docs-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-docs-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-jdbc-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-jdbc-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-libs-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-libs-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-pl-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-pl-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-python-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-python-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-server-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-server-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-tcl-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-tcl-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"rh-postgresql-test-7.3.21-2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"rh-postgresql-test-7.3.21-2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-postgresql / rh-postgresql-contrib / rh-postgresql-devel / etc");
}
