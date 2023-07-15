#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0466. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107208);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-12613",
    "CVE-2017-12615",
    "CVE-2017-12616",
    "CVE-2017-12617",
    "CVE-2017-15698",
    "CVE-2018-1304",
    "CVE-2018-1305"
  );
  script_xref(name:"RHSA", value:"2018:0466");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Web Server 3.1.0 Service Pack 2 (RHSA-2018:0466)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update is now available for Red Hat JBoss Web Server 3.1 for RHEL 6
and Red Hat JBoss Web Server 3.1 for RHEL 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Web Server is a fully integrated and certified set of
components for hosting Java web applications. It is comprised of the
Apache HTTP Server, the Apache Tomcat Servlet container, Apache Tomcat
Connector (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and
the Tomcat Native library.

This release of Red Hat JBoss Web Server 3.1 Service Pack 2 serves as
a replacement for Red Hat JBoss Web Server 3.1, and includes bug
fixes, which are documented in the Release Notes document linked to in
the References.

Security Fix(es) :

* apr: Out-of-bounds array deref in apr_time_exp*() functions
(CVE-2017-12613)

* tomcat: Remote Code Execution via JSP Upload (CVE-2017-12615)

* tomcat: Information Disclosure when using VirtualDirContext
(CVE-2017-12616)

* tomcat: Remote Code Execution bypass for CVE-2017-12615
(CVE-2017-12617)

* tomcat-native: Mishandling of client certificates can allow for OCSP
check bypass (CVE-2017-15698)

* tomcat: Incorrect handling of empty string URL in security
constraints can lead to unintended exposure of resources
(CVE-2018-1304)

* tomcat: Late application of security constraints can lead to
resource exposure for unauthorised users (CVE-2018-1305)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_jboss_web_server/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65f431f2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0466");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-12613");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-12615");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-12616");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-12617");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-15698");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1304");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1305");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat VirtualDirContext Class File Handling Remote JSP Source Code Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-vault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-vault-tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-vault-tomcat8");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2018:0466";
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
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-1.3.8-2.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-tomcat7-1.3.8-2.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-tomcat8-1.3.8-2.Final_redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat-native-1.2.8-11.redhat_11.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat-native-1.2.8-11.redhat_11.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tomcat-native-debuginfo-1.2.8-11.redhat_11.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat-native-debuginfo-1.2.8-11.redhat_11.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat-vault-1.1.6-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat-vault-tomcat7-1.1.6-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat-vault-tomcat8-1.1.6-1.Final_redhat_1.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-admin-webapps-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-docs-webapp-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-el-2.2-api-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-javadoc-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-jsp-2.2-api-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-jsvc-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-lib-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-log4j-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-selinux-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-servlet-3.0-api-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-webapps-7.0.70-25.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-admin-webapps-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-docs-webapp-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-el-2.2-api-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-javadoc-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-jsp-2.3-api-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-jsvc-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-lib-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-log4j-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-selinux-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-servlet-3.1-api-8.0.36-29.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat8-webapps-8.0.36-29.ep7.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mod_cluster-1.3.8-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mod_cluster-tomcat7-1.3.8-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mod_cluster-tomcat8-1.3.8-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tomcat-native-1.2.8-11.redhat_11.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tomcat-native-debuginfo-1.2.8-11.redhat_11.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat-vault-1.1.6-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat-vault-tomcat7-1.1.6-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat-vault-tomcat8-1.1.6-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-admin-webapps-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-docs-webapp-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-el-2.2-api-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-javadoc-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-jsp-2.2-api-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-jsvc-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-lib-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-log4j-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-selinux-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-servlet-3.0-api-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat7-webapps-7.0.70-25.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-admin-webapps-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-docs-webapp-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-el-2.2-api-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-javadoc-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-jsp-2.3-api-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-jsvc-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-lib-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-log4j-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-selinux-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-servlet-3.1-api-8.0.36-29.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tomcat8-webapps-8.0.36-29.ep7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_cluster / mod_cluster-tomcat7 / mod_cluster-tomcat8 / etc");
  }
}
