#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1835. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102140);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-4978", "CVE-2017-7525");
  script_xref(name:"RHSA", value:"2017:1835");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2017:1835)");
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
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This release of Red Hat JBoss Enterprise Application Platform 7.0.7
serves as a replacement for Red Hat JBoss Enterprise Application
Platform 7.0.6, and includes bug fixes and enhancements, which are
documented in the Release Notes linked to in the References.

Security Fix(es) :

* A deserialization flaw was discovered in jackson-databind which
could allow an unauthenticated user to perform code execution by
sending maliciously crafted input to the readValue method of the
ObjectMapper. (CVE-2017-7525)

* It was found that use of a JMS ObjectMessage does not safely handle
user-supplied data when deserializing objects. A remote attacker could
use this flaw to execute arbitrary code with the permissions of the
application using the JMS ObjectMessage. (CVE-2016-4978)

Red Hat would like to thank Liao Xinxi (NSFOCUS) for reporting
CVE-2017-7525."
  );
  # https://access.redhat.com/documentation/en/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7525"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-xnio-base");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-web-console-eap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2017:1835";
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

  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-cli-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-commons-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-core-client-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-dto-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hornetq-protocol-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-hqclient-protocol-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-client-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-jms-server-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-journal-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-native-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-ra-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-selector-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-server-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-activemq-artemis-service-extensions-1.1.0-18.SP21_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-glassfish-jsf-2.2.12-2.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-5.0.14-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-core-5.0.14-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-entitymanager-5.0.14-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-envers-5.0.14-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-infinispan-5.0.14-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-hibernate-java8-5.0.14-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-api-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-impl-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-common-spi-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-core-api-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-core-impl-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-deployers-common-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-jdbc-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-ironjacamar-validator-1.3.7-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jackson-databind-2.5.4-2.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-modules-1.5.4-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-remoting-4.0.23-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-xnio-base-3.4.6-1.Final_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-async-http-servlet-3.0-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-atom-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-cdi-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-client-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-crypto-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jackson2-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxb-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jaxrs-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jettison-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jose-jwt-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-jsapi-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-json-p-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-multipart-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-spring-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-validator-provider-11-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-resteasy-yaml-provider-3.0.19-6.SP4_redhat_1.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-7.0.7-4.GA_redhat_3.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-javadocs-7.0.7-3.GA_redhat_4.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-modules-7.0.7-4.GA_redhat_3.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-wildfly-web-console-eap-2.8.30-1.Final_redhat_1.1.ep7.el7")) flag++;

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
