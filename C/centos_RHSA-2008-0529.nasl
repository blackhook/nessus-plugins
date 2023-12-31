#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0529 and 
# CentOS Errata and Security Advisory 2008:0529 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33142);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-0960", "CVE-2008-2292");
  script_bugtraq_id(29212, 29623);
  script_xref(name:"RHSA", value:"2008:0529");

  script_name(english:"CentOS 3 / 4 / 5 : net-snmp (CESA-2008:0529)");
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

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Simple Network Management Protocol (SNMP) is a protocol used for
network management.

A flaw was found in the way Net-SNMP checked an SNMPv3 packet's
Keyed-Hash Message Authentication Code (HMAC). An attacker could use
this flaw to spoof an authenticated SNMPv3 packet. (CVE-2008-0960)

A buffer overflow was found in the Perl bindings for Net-SNMP. This
could be exploited if an attacker could convince an application using
the Net-SNMP Perl module to connect to a malicious SNMP agent.
(CVE-2008-2292)

All users of net-snmp should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/014970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ce0318a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/014971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d46f8e65"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/014980.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b76e169"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/014983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ce8c587"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015014.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e04fe41"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015015.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b05a3829"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dcbf0ab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?170e07e5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/12");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-5.0.9-2.30E.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-devel-5.0.9-2.30E.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-libs-5.0.9-2.30E.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-perl-5.0.9-2.30E.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-utils-5.0.9-2.30E.24")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"net-snmp-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-5.1.2-11.c4.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"net-snmp-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"net-snmp-devel-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-devel-5.1.2-11.c4.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"net-snmp-devel-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"net-snmp-libs-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-libs-5.1.2-11.c4.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"net-snmp-libs-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"net-snmp-perl-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-perl-5.1.2-11.c4.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"net-snmp-perl-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"net-snmp-utils-5.1.2-11.el4_6.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"net-snmp-utils-5.1.2-11.c4.11.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"net-snmp-utils-5.1.2-11.el4_6.11.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"net-snmp-5.3.1-24.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-devel-5.3.1-24.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-libs-5.3.1-24.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-perl-5.3.1-24.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"net-snmp-utils-5.3.1-24.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-devel / net-snmp-libs / net-snmp-perl / etc");
}
