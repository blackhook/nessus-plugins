#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0971 and 
# CentOS Errata and Security Advisory 2008:0971 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37176);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-4309");
  script_bugtraq_id(32020);
  script_xref(name:"RHSA", value:"2008:0971");

  script_name(english:"CentOS 3 / 4 / 5 : net-snmp (CESA-2008:0971)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Simple Network Management Protocol (SNMP) is a protocol used for
network management.

A denial-of-service flaw was found in the way Net-SNMP processes SNMP
GETBULK requests. A remote attacker who issued a specially crafted
request could cause the snmpd server to crash. (CVE-2008-4309)

Note: An attacker must have read access to the SNMP server in order to
exploit this flaw. In the default configuration, the community name
'public' grants read-only access. In production deployments, it is
recommended to change this default community name.

All users of net-snmp should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b494e88"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015366.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71f56659"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?791fcb7e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?529b2ed4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e3dbb69"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015386.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d6797c5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-devel-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-libs-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-perl-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-utils-5.0.9-2.30E.25")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-devel-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-libs-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-perl-5.1.2-13.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-utils-5.1.2-13.c4.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"net-snmp-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-devel-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-libs-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-perl-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-utils-5.3.1-24.el5_2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-devel / net-snmp-libs / net-snmp-perl / etc");
}
