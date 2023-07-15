#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0569 and 
# CentOS Errata and Security Advisory 2007:0569 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25777);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2449", "CVE-2007-2450");
  script_bugtraq_id(24475, 24476);
  script_xref(name:"RHSA", value:"2007:0569");

  script_name(english:"CentOS 5 : tomcat (CESA-2007:0569)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat packages that fix two security issues and a packaging
bug are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Tomcat is a servlet container for Java Servlet and JavaServer Pages
(JSP) technologies.

Some JSPs within the 'examples' web application did not escape user
provided data. If the JSP examples were accessible, this flaw could
allow a remote attacker to perform cross-site scripting attacks
(CVE-2007-2449).

Note: it is recommended the 'examples' web application not be
installed on a production system.

The Manager and Host Manager web applications did not escape user
provided data. If a user is logged in to the Manager or Host Manager
web application, an attacker could perform a cross-site scripting
attack (CVE-2007-2450).

Users of Tomcat should update to these erratum packages, which contain
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e099de5b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8de0b974"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/27");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-common-lib-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-server-lib-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-webapps-5.5.23-0jpp.1.0.4.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat5 / tomcat5-admin-webapps / tomcat5-common-lib / etc");
}
