#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0871. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76236);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1976");
  script_bugtraq_id(60186);
  script_xref(name:"RHSA", value:"2013:0871");

  script_name(english:"RHEL 5 / 6 : JBoss Web Server (RHSA-2013:0871)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat6 and tomcat7 packages that fix one security issue are
now available for JBoss Enterprise Web Server 2.0.0 for Red Hat
Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

A flaw was found in the way the tomcat6 and tomcat7 init scripts
handled the tomcat6-initd.log and tomcat7-initd.log log files. A
malicious web application deployed on Tomcat could use this flaw to
perform a symbolic link attack to change the ownership of an arbitrary
system file to that of the tomcat user, allowing them to escalate
their privileges to root. (CVE-2013-1976)

Note: With this update, tomcat6-initd.log and tomcat7-initd.log have
been moved to the /var/log/ directory.

Red Hat would like to thank Simon Fayer of Imperial College London for
reporting this issue.

Warning: Before applying the update, back up your existing JBoss
Enterprise Web Server installation (including all applications and
configuration files).

Users of Tomcat should upgrade to these updated packages, which
resolve this issue. Tomcat must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1976"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0871";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"mod_cluster") || rpm_exists(release:"RHEL6", rpm:"mod_cluster"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL5", reference:"tomcat6-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-admin-webapps-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-docs-webapp-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-el-1.0-api-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-javadoc-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-jsp-2.1-api-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-lib-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-log4j-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-servlet-2.5-api-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-webapps-6.0.35-12_patch_07.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-admin-webapps-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-docs-webapp-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-el-1.0-api-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-javadoc-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-jsp-2.2-api-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-lib-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-log4j-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-servlet-3.0-api-7.0.30-5_patch_03.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat7-webapps-7.0.30-5_patch_03.ep6.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"tomcat6-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-admin-webapps-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-docs-webapp-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-el-1.0-api-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-javadoc-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-jsp-2.1-api-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-lib-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-log4j-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-servlet-2.5-api-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-webapps-6.0.35-33_patch_07.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-admin-webapps-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-docs-webapp-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-el-1.0-api-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-javadoc-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-jsp-2.2-api-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-lib-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-log4j-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-servlet-3.0-api-7.0.30-7_patch_03.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat7-webapps-7.0.30-7_patch_03.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
  }
}
