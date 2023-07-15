#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1809 and 
# CentOS Errata and Security Advisory 2017:1809 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102020);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-5648", "CVE-2017-5664");
  script_xref(name:"RHSA", value:"2017:1809");

  script_name(english:"CentOS 7 : tomcat (CESA-2017:1809)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for tomcat is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

Security Fix(es) :

* A vulnerability was discovered in the error page mechanism in
Tomcat's DefaultServlet implementation. A crafted HTTP request could
cause undesired side effects, possibly including the removal or
replacement of the custom error page. (CVE-2017-5664)

* A vulnerability was discovered in Tomcat. When running an untrusted
application under a SecurityManager it was possible, under some
circumstances, for that application to retain references to the
request or response objects and thereby access and/or modify
information associated with another web application. (CVE-2017-5648)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-July/022511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddee7e8e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5648");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-lib-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.69-12.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-webapps-7.0.69-12.el7_3")) flag++;


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
