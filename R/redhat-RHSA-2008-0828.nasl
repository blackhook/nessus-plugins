#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0828. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63863);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1285", "CVE-2008-3273");
  script_bugtraq_id(30540);
  script_xref(name:"RHSA", value:"2008:0828");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2008:0828)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform (JBoss EAP) packages
that fix various security issues are now available for Red Hat
Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

JBoss EAP is a middleware platform for Java 2 Platform, Enterprise
Edition (J2EE) applications.

This release of JBoss EAP for Red Hat Enterprise Linux 5 contains the
JBoss Application Server and JBoss Seam. This release serves as a
replacement to JBoss EAP 4.3.0.GA, and fixes the following security
issues :

The JavaServer Faces (JSF) component was vulnerable to multiple
cross-site scripting (XSS) vulnerabilities. An attacker could use
these flaws to inject arbitrary web script or HTML. (CVE-2008-1285)

Unauthenticated users were able to access the status servlet, which
could allow remote attackers to acquire details about deployed web
contexts. (CVE-2008-3273)

These updated packages include bug fixes and enhancements which are
not listed here. For a full list, refer to the JBoss EAP 4.3.0.CP01
release notes, linked to in the 'References' section of this advisory.

Warning: before applying this update, please back up the JBoss EAP
'server/[configuration]/deploy/' directory, and any customized
configuration files.

All users of JBoss EAP on Red Hat Enterprise Linux 5 are advised to
upgrade to these updated packages, which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-3273"
  );
  # http://redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/4.3.0.cp01/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bdf7206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:0828"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-native42");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0828";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-4"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"asm-1.5.3-1jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cglib-2.1.3-2jpp.ep1.6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"concurrent-1.3.4-8jpp.ep1.6.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaf-1.1.0-0jpp.ep1.11.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-javamail-1.4.0-0jpp.ep1.9.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-1.2_08-0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-3.2.1-1.patch02.1jpp.ep1.3.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-javadoc-3.2.1-1.patch02.1jpp.ep1.3.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-3.2.1-1jpp.ep1.7.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-javadoc-3.2.1-1jpp.ep1.7.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP03.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aop-1.5.5-1.CP01.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-cache-1.4.1-4.SP9.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-messaging-1.4.0-1.SP3_CP02.0jpp.ep1.6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.2.2-3.SP7.0jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-1.2.1-3.JBPAPP_4_3_0_GA.ep1.5.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-docs-1.2.1-3.JBPAPP_4_3_0_GA.ep1.5.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.3.0-2.GA_CP01.ep1.6.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.2.3-1.SP5_CP01.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-2.0.1-2.SP2_CP01.0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-native42-2.0.1-2.SP2_CP01.0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossxb-1.0.0-2.SP1.0jpp.ep1.2.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jcommon-1.0.12-1jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jfreechart-1.0.9-1jpp.ep1.3.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-2.4.2-1.GA_CP01.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-4.3.0-2.GA_CP01.ep1.4.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asm / cglib / concurrent / glassfish-jaf / glassfish-javamail / etc");
  }
}
