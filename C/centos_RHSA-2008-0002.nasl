#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0002 and 
# CentOS Errata and Security Advisory 2008:0002 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29931);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-0003");
  script_bugtraq_id(27172);
  script_xref(name:"RHSA", value:"2008:0002");

  script_name(english:"CentOS 4 / 5 : tog-pegasus (CESA-2008:0002)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tog-pegasus packages that fix a security issue are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
Management (WBEM) services. WBEM is a platform and resource
independent DMTF standard that defines a common information model, and
communication protocol for monitoring and controlling resources.

During a security audit, a stack-based buffer overflow flaw was found
in the PAM authentication code in the OpenPegasus CIM management
server. An unauthenticated remote user could trigger this flaw and
potentially execute arbitrary code with root privileges.
(CVE-2008-0003)

Note that the tog-pegasus packages are not installed by default on Red
Hat Enterprise Linux. The Red Hat Security Response Team believes that
it would be hard to remotely exploit this issue to execute arbitrary
code, due to the default SELinux targeted policy on Red Hat Enterprise
Linux 4 and 5, and the SELinux memory protection tests enabled by
default on Red Hat Enterprise Linux 5.

Users of tog-pegasus should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages the tog-pegasus service should be restarted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9b34e51"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7229aeb9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55e8cd9d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014599.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7d7baef"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa27cb74"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tog-pegasus packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tog-pegasus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tog-pegasus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tog-pegasus-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/14");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"tog-pegasus-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"tog-pegasus-2.5.1-5.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"tog-pegasus-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"tog-pegasus-devel-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"tog-pegasus-devel-2.5.1-5.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"tog-pegasus-devel-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"tog-pegasus-test-2.5.1-5.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"tog-pegasus-test-2.5.1-5.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"tog-pegasus-test-2.5.1-5.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"tog-pegasus-2.6.1-2.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tog-pegasus-devel-2.6.1-2.el5_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tog-pegasus / tog-pegasus-devel / tog-pegasus-test");
}
