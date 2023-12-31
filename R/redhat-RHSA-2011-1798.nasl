#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1798. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64011);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4085", "CVE-2011-4314");
  script_bugtraq_id(47785, 50720);
  script_xref(name:"RHSA", value:"2011:1798");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2011:1798)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform 5.1.2 packages that fix
two security issues, various bugs, and add several enhancements are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

JBoss Enterprise Application Platform is a platform for Java
applications, which integrates the JBoss Application Server with JBoss
Hibernate and JBoss Seam. OpenID4Java allows you to implement OpenID
authentication in your Java applications. OpenID4Java is a Technology
Preview.

This JBoss Enterprise Application Platform 5.1.2 release for Red Hat
Enterprise Linux 6 serves as a replacement for JBoss Enterprise
Application Platform 5.1.1.

These updated packages include bug fixes and enhancements. Refer to
the JBoss Enterprise Application Platform 5.1.2 Release Notes for
information on the most significant of these changes. The Release
Notes will be available shortly from
https://docs.redhat.com/docs/en-US/index.html

The following security issues are also fixed with this release :

It was found that the invoker servlets, deployed by default via
httpha-invoker, only performed access control on the HTTP GET and POST
methods, allowing remote attackers to make unauthenticated requests by
using different HTTP methods. Due to the second layer of
authentication provided by a security interceptor, this issue is not
exploitable on default installations unless an administrator has
misconfigured the security interceptor or disabled it. (CVE-2011-4085)

It was found that the Attribute Exchange (AX) extension of OpenID4Java
was not checking to ensure attributes were signed. If AX was being
used to receive information that an application only trusts the
identity provider to assert, a remote attacker could use this flaw to
conduct man-in-the-middle attacks and compromise the integrity of the
information via a specially crafted request. By default, only the
JBoss Seam openid example application uses OpenID4Java.
(CVE-2011-4314)

Warning: Before applying this update, back up the
'jboss-as/server/[PROFILE]/deploy/' directory and any other customized
configuration files of your JBoss Enterprise Application Platform.

All users of JBoss Enterprise Application Platform 5.1.1 on Red Hat
Enterprise Linux 6 are advised to upgrade to these updated packages.
The JBoss server process must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-4314"
  );
  # https://docs.redhat.com/docs/en-US/index.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/offerings/techpreview/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2011:1798"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facelets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-eap5-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-clustered");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-tp-licenses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosssx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-hibernate-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-as-5-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-cache-v3-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org-mc4j-ems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation-webapp-idp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation-webapp-pdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation-webapp-sts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-ant-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-common-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-client-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-comm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-dbutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-native-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugindoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-filetemplate-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jboss-as-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jmx-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-modules-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-platform-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugin-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginAnnotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginGen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugins-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-rtfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1798";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-client-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.2.12-4.patch_02.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cglib-2.2-5.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"facelets-1.1.15-3.B1_patch_01.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jaxb-2.1.12-10_patch_02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jsf-1.2_13-5_patch_01.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jacorb-jboss-2.3.1-10.patch_03.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jakarta-commons-logging-jboss-1.1-10.3_patch_02.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-aop2-2.1.6-2.CP03.1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cache-core-3.2.8-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cl-2.0.10-1.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-cluster-ha-client-1.1.4-1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-common-core-2.2.18-1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"jboss-eap5-native-5.1.2-1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jboss-eap5-native-5.1.2-1.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-core-1.3.8-0.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-proxy-clustered-1.0.3-2.SP1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-proxy-impl-1.0.6-2.SP2.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-el-1.0_02-0.CR6.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-messaging-1.4.8-9.SP5.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-naming-5.0.3-3.CP01.3.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-remoting-2.5.4-9.SP3.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-2.2.5.EAP5-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-docs-2.2.5.EAP5-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-examples-2.2.5.EAP5-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-runtime-2.2.5.EAP5-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-spi-2.0.4-6.SP8.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-5.1.2-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-client-5.1.2-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-messaging-5.1.2-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-tp-licenses-5.1.2-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-ws-cxf-5.1.2-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-ws-native-5.1.2-8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbosssx2-2.0.4-6.SP8.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-4.6.1-11.CP12.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-javadoc-4.6.1-11.CP12.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-2.1.12-1.4_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-el-1.0-api-2.1.12-1.4_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-jsp-2.1-api-2.1.12-1.4_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-lib-2.1.12-1.4_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-servlet-2.5-api-2.1.12-1.4_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-3.1.2-7.SP11.4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-common-1.1.0-6.SP8_patch_01.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-framework-3.1.2-6.SP10.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-spi-1.1.2-5.SP7.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jgroups-2.6.20-1.1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-embedded-1.3.4-18.SP5.8.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-hibernate-plugin-3.0.0-13.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-jboss-as-5-plugin-3.0.0-12.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jopr-jboss-cache-v3-plugin-3.0.0-14.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-demo-1.0.10-3.2.GA_CP02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-jbossas-1.0.10-3.2.GA_CP02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-jbossweb2-1.0.10-3.2.GA_CP02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_cluster-native-1.0.10-3.1.1.GA_CP02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_cluster-native-1.0.10-3.1.1.GA_CP02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-tomcat6-1.0.10-3.2.GA_CP02.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"org-mc4j-ems-1.2.15.1-7.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketlink-federation-2.0.2-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketlink-federation-webapp-idp-2.0.2-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketlink-federation-webapp-pdp-2.0.2-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketlink-federation-webapp-sts-2.0.2-1.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-1.2.1-9.CP02.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-examples-1.2.1-9.CP02.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-javadoc-1.2.1-9.CP02.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-manual-1.2.1-9.CP02.5.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-eap-docs-5.1.2-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rh-eap-docs-examples-5.1.2-6.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-ant-bundle-common-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-common-parent-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-client-api-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-comm-api-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-dbutils-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-domain-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-gui-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-native-system-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-parent-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-plugin-api-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-plugin-container-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-plugindoc-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-core-util-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-filetemplate-bundle-common-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-helpers-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-jboss-as-common-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-jmx-plugin-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-modules-parent-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-parent-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-platform-plugin-3.0.0-13.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-plugin-validator-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-pluginAnnotations-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-pluginGen-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-plugins-parent-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rhq-rtfilter-3.0.0-20.EmbJopr4.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"slf4j-1.5.8-10_patch_01.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xalan-j2-2.7.1-6_patch_05.1.ep5.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-cxf / cglib / facelets / glassfish-jaxb / glassfish-jsf / etc");
  }
}
