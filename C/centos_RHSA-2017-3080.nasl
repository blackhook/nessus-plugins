#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3080 and 
# CentOS Errata and Security Advisory 2017:3080 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104256);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-12615",
    "CVE-2017-12617",
    "CVE-2017-5647",
    "CVE-2017-5664"
  );
  script_xref(name:"RHSA", value:"2017:3080");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"CentOS 6 : tomcat6 (CESA-2017:3080)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for tomcat6 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

Security Fix(es) :

* A vulnerability was discovered in Tomcat's handling of pipelined
requests when 'Sendfile' was used. If sendfile processing completed
quickly, it was possible for the Processor to be added to the
processor cache twice. This could lead to invalid responses or
information disclosure. (CVE-2017-5647)

* A vulnerability was discovered in the error page mechanism in
Tomcat's DefaultServlet implementation. A crafted HTTP request could
cause undesired side effects, possibly including the removal or
replacement of the custom error page. (CVE-2017-5664)

* Two vulnerabilities were discovered in Tomcat where if a servlet
context was configured with readonly=false and HTTP PUT requests were
allowed, an attacker could upload a JSP file to that context and
achieve code execution. (CVE-2017-12615, CVE-2017-12617)");
  # https://lists.centos.org/pipermail/centos-announce/2017-October/022610.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a18954a2");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat6 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-admin-webapps-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-docs-webapp-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-el-2.1-api-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-javadoc-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-jsp-2.1-api-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-lib-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-servlet-2.5-api-6.0.24-111.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-webapps-6.0.24-111.el6_9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
}
