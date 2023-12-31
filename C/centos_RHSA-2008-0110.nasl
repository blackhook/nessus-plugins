#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0110 and 
# CentOS Errata and Security Advisory 2008:0110 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31138);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-6698", "CVE-2008-0658");
  script_bugtraq_id(26245, 27778);
  script_xref(name:"RHSA", value:"2008:0110");

  script_name(english:"CentOS 4 / 5 : openldap (CESA-2008:0110)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix security issues are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols for accessing directory services.

These updated openldap packages fix a flaw in the way the OpenLDAP
slapd daemon handled modify and modrdn requests with NOOP control on
objects stored in a Berkeley DB (BDB) storage backend. An
authenticated attacker with permission to perform modify or modrdn
operations on such LDAP objects could cause slapd to crash.
(CVE-2007-6698, CVE-2008-0658)

Users of openldap should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-February/014689.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aedc486c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-February/014690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df0efe34"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-February/014692.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b727b99f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-February/014702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a840305e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-February/014703.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8a4e482"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"compat-openldap-2.1.30-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"compat-openldap-2.1.30-8.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"compat-openldap-2.1.30-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-2.2.13-8.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-clients-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-clients-2.2.13-8.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-clients-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-devel-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-devel-2.2.13-8.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-devel-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-servers-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-servers-2.2.13-8.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-servers-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openldap-servers-sql-2.2.13-8.el4_6.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-servers-sql-2.2.13-8.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openldap-servers-sql-2.2.13-8.el4_6.4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"compat-openldap-2.3.27_2.2.29-8.el5_1.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-2.3.27-8.el5_1.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-clients-2.3.27-8.el5_1.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-devel-2.3.27-8.el5_1.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-2.3.27-8.el5_1.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-sql-2.3.27-8.el5_1.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
}
