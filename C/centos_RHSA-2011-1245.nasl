#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1245 and 
# CentOS Errata and Security Advisory 2011:1245 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56046);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-3192");
  script_bugtraq_id(49303);
  script_xref(name:"RHSA", value:"2011:1245");

  script_name(english:"CentOS 4 : httpd (CESA-2011:1245)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Apache HTTP Server is a popular web server.

A flaw was found in the way the Apache HTTP Server handled Range HTTP
headers. A remote attacker could use this flaw to cause httpd to use
an excessive amount of memory and CPU time via HTTP requests with a
specially crafted Range header. (CVE-2011-3192)

All httpd users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017710.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a01fb5d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017711.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbdb62c6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/02");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-devel-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-devel-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-manual-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-manual-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-suexec-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-suexec-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mod_ssl-2.0.52-48.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mod_ssl-2.0.52-48.ent.centos4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / mod_ssl");
}
