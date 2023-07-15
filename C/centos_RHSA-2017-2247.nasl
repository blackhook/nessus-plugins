#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2247 and 
# CentOS Errata and Security Advisory 2017:2247 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102756);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797");
  script_xref(name:"RHSA", value:"2017:2247");

  script_name(english:"CentOS 7 : tomcat (CESA-2017:2247)");
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
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

The following packages have been upgraded to a later upstream version:
tomcat (7.0.76). (BZ#1414895)

Security Fix(es) :

* The Realm implementations did not process the supplied password if
the supplied user name did not exist. This made a timing attack
possible to determine valid user names. Note that the default
configuration includes the LockOutRealm which makes exploitation of
this vulnerability harder. (CVE-2016-0762)

* It was discovered that a malicious web application could bypass a
configured SecurityManager via a Tomcat utility method that was
accessible to web applications. (CVE-2016-5018)

* It was discovered that when a SecurityManager was configured,
Tomcat's system property replacement feature for configuration files
could be used by a malicious web application to bypass the
SecurityManager and read system properties that should not be visible.
(CVE-2016-6794)

* It was discovered that a malicious web application could bypass a
configured SecurityManager via manipulation of the configuration
parameters for the JSP Servlet. (CVE-2016-6796)

* It was discovered that it was possible for a web application to
access any global JNDI resource whether an explicit ResourceLink had
been configured or not. (CVE-2016-6797)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004575.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0d60064"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5018");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-lib-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.76-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tomcat-webapps-7.0.76-2.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
