#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1034 and 
# CentOS Errata and Security Advisory 2014:1034 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77060);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-0119");
  script_xref(name:"RHSA", value:"2014:1034");

  script_name(english:"CentOS 7 : tomcat (CESA-2014:1034)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat packages that fix one security issue are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

It was found that, in certain circumstances, it was possible for a
malicious web application to replace the XML parsers used by Apache
Tomcat to process XSLTs for the default servlet, JSP documents, tag
library descriptors (TLDs), and tag plug-in configuration files. The
injected XML parser(s) could then bypass the limits imposed on XML
external entities and/or gain access to the XML files processed for
other web applications deployed on the same Apache Tomcat instance.
(CVE-2014-0119)

All Tomcat users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. Tomcat must be
restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-August/020478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fb9bc1b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0119");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-lib-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.42-8.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-webapps-7.0.42-8.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
