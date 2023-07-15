#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2921 and 
# CentOS Errata and Security Advisory 2018:2921 respectively.
#

include('compat.inc');

if (description)
{
  script_id(118156);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/08");

  script_cve_id("CVE-2018-1336");
  script_xref(name:"RHSA", value:"2018:2921");

  script_name(english:"CentOS 7 : tomcat (CESA-2018:2921)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for tomcat is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

Security Fix(es) :

* tomcat: A bug in the UTF-8 decoder can lead to DoS (CVE-2018-1336)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.");
  # https://lists.centos.org/pipermail/centos-announce/2018-October/023067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbddcbdc");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/17");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-lib-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.76-8.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-webapps-7.0.76-8.el7_5")) flag++;


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
