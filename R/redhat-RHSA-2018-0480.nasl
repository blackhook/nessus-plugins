#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0480. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108324);
  script_version("1.6");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2017-12174", "CVE-2017-12196", "CVE-2017-15089", "CVE-2017-15095", "CVE-2017-17485", "CVE-2017-7561", "CVE-2018-1048", "CVE-2018-5968");
  script_xref(name:"RHSA", value:"2018:0480");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2018:0480)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat JBoss Enterprise Application
Platform 7.1 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This release of Red Hat JBoss Enterprise Application Platform 7.1.1
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 7.1.0, and includes bug fixes and enhancements, which are
documented in the Release Notes document linked to in the References.

Security Fix(es) :

* artemis/hornetq: memory exhaustion via UDP and JGroups discovery
(CVE-2017-12174)

* infinispan: Unsafe deserialization of malicious object injected into
data cache (CVE-2017-15089)

* jackson-databind: Unsafe deserialization due to incomplete black
list (incomplete fix for CVE-2017-7525) (CVE-2017-15095)

* jackson-databind: Unsafe deserialization due to incomplete black
list (incomplete fix for CVE-2017-15095) (CVE-2017-17485)

* resteasy: Vary header not added by CORS filter leading to cache
poisoning (CVE-2017-7561)

* undertow: Client can use bogus uri in Digest authentication
(CVE-2017-12196)

* undertow: ALLOW_ENCODED_SLASH option not taken into account in the
AjpRequestParser (CVE-2018-1048)

* jackson-databind: unsafe deserialization due to incomplete blacklist
(incomplete fix for CVE-2017-7525 and CVE-2017-17485) (CVE-2018-5968)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-17485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-5968"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-core-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-dto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hornetq-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-hqclient-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-jdbc-store");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbosstxbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jbossxts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-jastow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/14");
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
  rhsa = "RHSA-2018:0480";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-cli-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-commons-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-core-client-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-dto-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hornetq-protocol-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hqclient-protocol-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jdbc-store-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-client-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-server-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-journal-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-native-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-ra-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-selector-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-server-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-service-extensions-1.5.5.009-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-3.1.13-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-rt-3.1.13-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-services-3.1.13-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-apache-cxf-tools-3.1.13-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-glassfish-jsf-2.2.13-6.SP5_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-5.1.12-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-core-5.1.12-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-entitymanager-5.1.12-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-envers-5.1.12-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-infinispan-5.1.12-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-java8-5.1.12-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-8.2.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-cachestore-jdbc-8.2.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-cachestore-remote-8.2.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-client-hotrod-8.2.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-commons-8.2.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-infinispan-core-8.2.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-api-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-impl-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-spi-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-core-api-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-core-impl-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-deployers-common-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-jdbc-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-validator-1.4.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-annotations-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-core-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-databind-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-datatype-jdk8-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-datatype-jsr310-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-jaxrs-base-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-jaxrs-json-provider-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-module-jaxb-annotations-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-modules-java8-2.8.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-logmanager-2.0.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-cli-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-core-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-eap6.4-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-eap6.4-to-eap7.0-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-eap6.4-to-eap7.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-eap7.0-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-eap7.0-to-eap7.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-eap7.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly10.0-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly10.0-to-eap7.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly10.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly10.1-to-eap7.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly8.2-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly8.2-to-eap7.0-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly8.2-to-eap7.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly9.0-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly9.0-to-eap7.0-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-server-migration-wildfly9.0-to-eap7.1-1.0.3-6.Final_redhat_6.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jbossws-cxf-5.1.10-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-compensations-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-jbosstxbridge-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-jbossxts-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-jts-idlj-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-jts-integration-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-restat-api-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-restat-bridge-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-restat-integration-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-restat-util-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-narayana-txframework-5.5.31-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-api-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-bindings-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-common-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-config-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-federation-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-api-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-impl-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-idm-simple-schema-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-impl-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-picketlink-wildfly8-2.5.5-10.SP9_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-atom-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-cdi-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-client-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-crypto-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson2-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxb-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxrs-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jettison-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jose-jwt-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jsapi-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-json-p-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-multipart-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-spring-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-validator-provider-11-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-yaml-provider-3.0.25-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-undertow-1.4.18-4.SP2_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-undertow-jastow-2.0.3-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-7.1.1-4.GA_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-elytron-1.1.8-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-http-client-common-1.0.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-http-ejb-client-1.0.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-http-naming-client-1.0.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-http-transaction-client-1.0.9-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-javadocs-7.1.1-3.GA_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-modules-7.1.1-4.GA_redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-2.1.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-bindings-2.1.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-policy-2.1.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-common-2.1.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-dom-2.1.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-policy-stax-2.1.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wss4j-ws-security-stax-2.1.11-1.redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-xml-security-2.0.9-1.redhat_1.1.ep7.el7")) flag++;

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
