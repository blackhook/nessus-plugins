#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0131. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121325);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/23");

  script_cve_id("CVE-2018-11784", "CVE-2018-8034");
  script_xref(name:"RHSA", value:"2019:0131");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Web Server 3.1 Service Pack 6 (RHSA-2019:0131)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update is now available for Red Hat JBoss Web Server 3.1 for RHEL 6
and Red Hat JBoss Web Server 3.1 for RHEL 7.

Red Hat Product Security has rated this release as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Web Server is a fully integrated and certified set of
components for hosting Java web applications. It is comprised of the
Apache HTTP Server, the Apache Tomcat Servlet container, Apache Tomcat
Connector (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and
the Tomcat Native library.

This release of Red Hat JBoss Web Server 3.1 Service Pack 5 serves as
a replacement for Red Hat JBoss Web Server 3.1, and includes bug
fixes, which are documented in the Release Notes document linked to in
the References.

Security Fix(es) :

* tomcat: host name verification missing in WebSocket client
(CVE-2018-8034)

* tomcat: Open redirect in default servlet (CVE-2018-11784)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-8034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-11784"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-servlet-3.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:0131";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL6", rpm:"mod_cluster") || rpm_exists(release:"RHEL7", rpm:"mod_cluster"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat-native-1.2.17-18.redhat_18.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat-native-1.2.17-18.redhat_18.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat-native-debuginfo-1.2.17-18.redhat_18.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat-native-debuginfo-1.2.17-18.redhat_18.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-admin-webapps-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-docs-webapp-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-el-2.2-api-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-javadoc-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-jsp-2.2-api-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-jsvc-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-lib-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-log4j-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-selinux-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-servlet-3.0-api-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-webapps-7.0.70-31.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-admin-webapps-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-docs-webapp-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-el-2.2-api-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-javadoc-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-jsp-2.3-api-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-jsvc-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-lib-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-log4j-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-selinux-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-servlet-3.1-api-8.0.36-35.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-webapps-8.0.36-35.ep7.el6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tomcat-native-1.2.17-18.redhat_18.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tomcat-native-debuginfo-1.2.17-18.redhat_18.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-admin-webapps-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-docs-webapp-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-el-2.2-api-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-javadoc-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-jsp-2.2-api-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-jsvc-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-lib-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-log4j-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-selinux-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-servlet-3.0-api-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-webapps-7.0.70-31.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-admin-webapps-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-docs-webapp-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-el-2.2-api-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-javadoc-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-jsp-2.3-api-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-jsvc-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-lib-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-log4j-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-selinux-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-servlet-3.1-api-8.0.36-35.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-webapps-8.0.36-35.ep7.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat-native / tomcat-native-debuginfo / tomcat7 / etc");
  }
}
