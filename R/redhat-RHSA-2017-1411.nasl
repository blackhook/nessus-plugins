#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1411. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112259);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-9606", "CVE-2017-2595", "CVE-2017-2666", "CVE-2017-2670");
  script_xref(name:"RHSA", value:"2017:1411");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2017:1411)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 7.0 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This release of Red Hat JBoss Enterprise Application Platform 7.0.6
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 7.0.5, and includes bug fixes and enhancements, which are
documented in the Release Notes document linked to in the References.

Security Fix(es) :

* It was discovered that under certain conditions RESTEasy could be
forced to parse a request with YamlProvider, resulting in
unmarshalling of potentially untrusted data. An attacker could
possibly use this flaw execute arbitrary code with the permissions of
the application using RESTEasy. (CVE-2016-9606)

* It was found that the log file viewer in Red Hat JBoss Enterprise
Application 6 and 7 allows arbitrary file read to authenticated user
via path traversal. (CVE-2017-2595)

* It was discovered that the code that parsed the HTTP request line
permitted invalid characters. This could be exploited, in conjunction
with a proxy that also permitted the invalid characters but with a
different interpretation, to inject data into the HTTP response. By
manipulating the HTTP response the attacker could poison a web-cache,
perform an XSS attack, or obtain sensitive information from requests
other than their own. (CVE-2017-2666)

* It was found that with non-clean TCP close, Websocket server gets
into infinite loop on every IO thread, effectively causing DoS.
(CVE-2017-2670)

Red Hat would like to thank Moritz Bechler (AgNO3 GmbH & Co. KG) for
reporting CVE-2016-9606 and Gregory Ramsperger and Ryan Moak for
reporting CVE-2017-2670. The CVE-2017-2666 issue was discovered by
Radim Hatlapatka (Red Hat)."
  );
  # https://access.redhat.com/documentation/en/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2670"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-commons-logging-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-el-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-spi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
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
  rhsa = "RHSA-2017:1411";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"eap7-jboss"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-cli-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-commons-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-core-client-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-dto-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hornetq-protocol-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hqclient-protocol-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-client-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-server-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-journal-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-native-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-ra-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-selector-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-server-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-service-extensions-1.1.0-17.SP20_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-3.1.10-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-rt-3.1.10-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-services-3.1.10-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-tools-3.1.10-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-commons-logging-jboss-logmanager-1.0.0-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-glassfish-javamail-1.5.5-2.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-5.0.13-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-core-5.0.13-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-entitymanager-5.0.13-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-envers-5.0.13-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-infinispan-5.0.13-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-java8-5.0.13-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-validator-5.2.5-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-validator-cdi-5.2.5-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-8.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-cachestore-jdbc-8.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-cachestore-remote-8.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-client-hotrod-8.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-commons-8.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-core-8.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-api-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-impl-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-spi-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-core-api-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-core-impl-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-deployers-common-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-jdbc-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-validator-1.3.6-2.Final_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-ejb-client-2.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-el-api_3.0_spec-1.0.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-logging-3.3.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-metadata-10.0.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-metadata-appclient-10.0.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-metadata-common-10.0.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-metadata-ear-10.0.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-metadata-ejb-10.0.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-metadata-web-10.0.1-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-modules-1.5.3-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-remoting-4.0.22-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-security-negotiation-3.0.4-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-xnio-base-3.4.4-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-common-3.1.5-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-common-tools-1.2.3-2.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-cxf-5.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-spi-3.1.4-2.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketbox-4.9.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketbox-infinispan-4.9.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-api-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-bindings-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-common-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-config-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-federation-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-api-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-impl-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-simple-schema-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-impl-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-wildfly8-2.5.5-8.SP7_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-async-http-servlet-3.0-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-atom-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-cdi-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-client-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-crypto-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson2-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxb-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxrs-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jettison-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jose-jwt-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jsapi-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-json-p-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-multipart-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-spring-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-validator-provider-11-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-yaml-provider-3.0.19-5.SP3_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-undertow-1.3.28-4.Final_redhat_4.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-7.0.6-4.GA_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-elytron-1.0.4-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-javadocs-7.0.6-2.GA_redhat_3.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-modules-7.0.6-4.GA_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-2.1.8-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-bindings-2.1.8-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-policy-2.1.8-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-common-2.1.8-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-dom-2.1.8-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-policy-stax-2.1.8-2.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-stax-2.1.8-2.redhat_1.1.ep7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-activemq-artemis / eap7-activemq-artemis-cli / etc");
  }
}
