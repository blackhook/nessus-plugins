#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1649. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63905);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0217", "CVE-2009-1380", "CVE-2009-2405", "CVE-2009-2625", "CVE-2009-3554");
  script_xref(name:"RHSA", value:"2009:1649");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2009:1649)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform (JBEAP) 4.3 packages
that fix multiple security issues, several bugs, and add enhancements
are now available for Red Hat Enterprise Linux 5 as JBEAP 4.3.0.CP07.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

JBoss Enterprise Application Platform is the market leading platform
for innovative and scalable Java applications; integrating the JBoss
Application Server, with JBoss Hibernate and JBoss Seam into a
complete, simple enterprise solution.

This release of JBEAP for Red Hat Enterprise Linux 5 serves as a
replacement to JBEAP 4.3.0.CP06.

These updated packages include bug fixes and enhancements which are
detailed in the Release Notes, available shortly from:
http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform
/

The following security issues are also fixed with this release :

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xml-security. An
attacker could use this flaw to create a specially crafted XML file
that forges an XML signature, allowing the attacker to bypass
authentication that is based on the XML Signature specification.
(CVE-2009-0217)

Swatej Kumar discovered cross-site scripting (XSS) flaws in the JBoss
Application Server Web Console. An attacker could use these flaws to
present misleading data to an authenticated user, or execute arbitrary
scripting code in the context of the authenticated user's browser
session. (CVE-2009-2405)

A flaw was found in the way the Apache Xerces2 Java Parser processed
the SYSTEM identifier in DTDs. A remote attacker could provide a
specially crafted XML file, which once parsed by an application using
the Apache Xerces2 Java Parser, would lead to a denial of service
(application hang due to excessive CPU use). (CVE-2009-2625)

An information leak flaw was found in the twiddle command line client.
The JMX password was logged in plain text to 'twiddle.log'.
(CVE-2009-3554)

An XSS flaw was found in the JMX Console. An attacker could use this
flaw to present misleading data to an authenticated user, or execute
arbitrary scripting code in the context of the authenticated user's
browser session. (CVE-2009-1380)

Warning: Before applying this update, please backup the JBEAP
'server/[configuration]/deploy/' directory, and any other customized
configuration files.

All users of JBEAP 4.3 on Red Hat Enterprise Linux 5 are advised to
upgrade to these updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-0217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-1380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-2405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-2625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2009-3554"
  );
  # http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13c46bfa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2009:1649"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.3.0.GA_CP07-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-native42");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/09");
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
  rhsa = "RHSA-2009:1649";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-client-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxb-2.1.4-1.12.patch03.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxb-javadoc-2.1.4-1.12.patch03.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-1.2_13-2.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-3.2.4-1.SP1_CP09.0jpp.ep1.2.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-3.3.1-1.11GA_CP02.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-javadoc-3.3.1-1.11GA_CP02.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-3.3.2-2.5.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-javadoc-3.3.2-2.5.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP09.0jpp.ep1.2.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jacorb-2.3.0-1jpp.ep1.9.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aop-1.5.5-3.CP04.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-1.2.1-0jpp.ep1.3.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-messaging-1.4.0-3.SP3_CP09.4.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.2.3-3.SP1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-1.2.1-3.JBPAPP_4_3_0_GA.ep1.12.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-docs-1.2.1-3.JBPAPP_4_3_0_GA.ep1.12.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-2.0.2.FP-1.ep1.18.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-docs-2.0.2.FP-1.ep1.18.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.3.0-6.GA_CP07.4.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.3.0.GA_CP07-bin-4.3.0-6.GA_CP07.4.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-client-4.3.0-6.GA_CP07.4.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.2.3-1.SP5_CP08.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.0.0-6.CP12.0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-2.0.1-4.SP2_CP07.2.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-common-1.0.0-2.GA_CP05.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-framework-2.0.1-1.GA_CP05.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-native42-2.0.1-4.SP2_CP07.2.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jcommon-1.0.16-1.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jfreechart-1.0.13-2.3.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-2.4.7-1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"quartz-1.5.2-1jpp.patch01.ep1.4.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-4.3.0-6.GA_CP07.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-examples-4.3.0-6.GA_CP07.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xml-security-1.3.0-1.3.patch01.ep1.2.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glassfish-jaxb / glassfish-jaxb-javadoc / glassfish-jsf / etc");
  }
}
