#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1839. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112246);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2015-0254", "CVE-2016-4993", "CVE-2016-5406");
  script_xref(name:"RHSA", value:"2016:1839");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2016:1839)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 7.0.2, fix several bugs, and add various enhancements are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform 7 is an application
server that serves as a middleware platform and is built on open
standards and compliant with the Java EE 7 specification.

This release serves as a replacement for Red Hat JBoss Enterprise
Application Platform 7.0.1. It includes bug fixes and enhancements.
Refer to the JBoss Enterprise Application Platform 7.0.2 Release Notes
linked to in the References section for information about the most
significant bug fixes and enhancements included in this release.

Security Fix(es) :

* It was found that the Java Standard Tag Library (JSTL) allowed the
processing of untrusted XML documents to utilize external entity
references, which could access resources on the host system and,
potentially, allowing arbitrary code execution. (CVE-2015-0254)

* It was reported that EAP 7 Application Server/Undertow web server is
vulnerable to the injection of arbitrary HTTP headers, and also
response splitting, due to insufficient sanitization and validation of
user input before the input is used as part of an HTTP header value.
(CVE-2016-4993)

* The domain controller will not propagate its administrative RBAC
configuration to some slaves. An attacker could use this to escalate
their privileges. (CVE-2016-5406)

Red Hat would like to thank Calum Hutton (NCC Group) and Mikhail
Egorov (Odin) for reporting CVE-2016-4993. The CVE-2016-5406 issue was
discovered by Tomaz Cerar (Red Hat)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-0254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5406"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-dto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hornetq-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hqclient-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jms-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-journal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-jstl-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-idm-simple-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-wildfly8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-async-http-servlet-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson2-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jose-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-web-console-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1839";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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

  if (! (rpm_exists(release:"RHEL7", rpm:"eap7-jboss"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-cli-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-commons-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-core-client-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-dto-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hornetq-protocol-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hqclient-protocol-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-client-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-server-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-journal-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-native-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-ra-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-selector-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-server-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-service-extensions-1.1.0-15.SP18_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-3.1.6-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-rt-3.1.6-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-services-3.1.6-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-tools-3.1.6-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jberet-1.2.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jberet-core-1.2.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-jstl-api_1.2_spec-1.1.3-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-security-negotiation-3.0.3-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-common-3.1.3-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-cxf-5.1.5-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-spi-3.1.2-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jgroups-3.6.10-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-mod_cluster-1.3.3-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketbox-4.9.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketbox-infinispan-4.9.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-api-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-bindings-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-common-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-config-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-federation-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-api-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-impl-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-simple-schema-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-impl-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-wildfly8-2.5.5-3.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-async-http-servlet-3.0-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-atom-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-cdi-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-client-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-crypto-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson2-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxb-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxrs-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jettison-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jose-jwt-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jsapi-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-json-p-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-multipart-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-spring-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-validator-provider-11-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-yaml-provider-3.0.18-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-undertow-1.3.24-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-7.0.2-2.GA_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-javadocs-7.0.2-1.GA_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-modules-7.0.2-2.GA_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-web-console-eap-2.8.27-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-2.1.5-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-bindings-2.1.5-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-policy-2.1.5-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-common-2.1.5-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-dom-2.1.5-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-policy-stax-2.1.5-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-stax-2.1.5-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-xalan-j2-2.7.1-25.redhat_11.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-xml-security-2.0.6-1.redhat_1.1.ep7.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-activemq-artemis / eap7-activemq-artemis-cli / etc");
  }
}
