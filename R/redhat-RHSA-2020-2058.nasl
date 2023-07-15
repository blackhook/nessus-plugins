##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2058. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136494);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-10172",
    "CVE-2019-12423",
    "CVE-2019-17573",
    "CVE-2020-1719",
    "CVE-2020-1729",
    "CVE-2020-1732",
    "CVE-2020-1745",
    "CVE-2020-1757",
    "CVE-2020-7226",
    "CVE-2020-10705",
    "CVE-2020-10719"
  );
  script_xref(name:"RHSA", value:"2020:2058");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 6 : Red Hat JBoss Enterprise Application Platform 7.2.8 on RHEL 6 (RHSA-2020:2058)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2058 advisory.

  - jackson-mapper-asl: XML external entity similar to CVE-2016-3720 (CVE-2019-10172)

  - cxf: OpenId Connect token service does not properly validate the clientId (CVE-2019-12423)

  - cxf: reflected XSS in the services listing page (CVE-2019-17573)

  - undertow: Memory exhaustion issue in HttpReadListener via Expect: 100-continue header (CVE-2020-10705)

  - undertow: invalid HTTP request with large chunk size (CVE-2020-10719)

  - Wildfly: EJBContext principal is not popped back after invoking another EJB using a different Security
    Domain (CVE-2020-1719)

  - SmallRye: SecuritySupport class is incorrectly public and contains a static method to access the current
    threads context class loader (CVE-2020-1729)

  - Soteria: security identity corruption across concurrent threads (CVE-2020-1732)

  - undertow: AJP File Read/Inclusion Vulnerability (CVE-2020-1745)

  - undertow: servletPath is normalized incorrectly leading to dangerous application mapping which could
    result in security bypass (CVE-2020-1757)

  - cryptacular: excessive memory allocation during a decode operation (CVE-2020-7226)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10172");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12423");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17573");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1719");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1729");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1732");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1745");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1757");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7226");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10705");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10719");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1715075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1752770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1797006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1797011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1803241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1807305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1828459");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 200, 270, 284, 285, 400, 444, 522, 611, 770, 863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-ra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-service-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-activemq-artemis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-pkix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-bouncycastle-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-cryptacular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-el-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-orm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-serialization-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jasypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaee-security-soteria");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaee-security-soteria-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly10.1-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly11.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly12.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly8.2-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-wildfly9.0-to-eap7.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jgroups-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-profile-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-saml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-saml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-security-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-security-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-soap-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-saml-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xacml-saml-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xmlsec-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opensaml-xmlsec-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketbox-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-atom-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-client-microprofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jackson2-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxb-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jettison-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jose-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-jsapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-binding-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-json-p-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-multipart-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-rxjava2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-spring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-validator-provider-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-resteasy-yaml-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-smallrye-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-smallrye-health");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-cdi-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ws-commons-XmlSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-policy-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wss4j-ws-security-stax");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-activemq-artemis-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-cli-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-commons-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-core-client-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-dto-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-client-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-server-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-journal-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-ra-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-selector-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-server-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-service-extensions-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-tools-2.9.0-4.redhat_00010.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-3.2.12-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-rt-3.2.12-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-services-3.2.12-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-tools-3.2.12-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-1.60.0-2.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-mail-1.60.0-2.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-pkix-1.60.0-2.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-bouncycastle-prov-1.60.0-2.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-1.9.13-10.redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-core-asl-1.9.13-10.redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-jaxrs-1.9.13-10.redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-mapper-asl-1.9.13-10.redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codehaus-jackson-xc-1.9.13-10.redhat_00007.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-cryptacular-1.2.4-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-el-3.0.1-5.b08_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-el-impl-3.0.1-5.b08_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-javamail-1.6.2-2.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jsf-2.3.5-10.SP3_redhat_00008.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.0.21-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-commons-annotations-5.0.5-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-5.10.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-backend-jgroups-5.10.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-backend-jms-5.10.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-engine-5.10.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-orm-5.10.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-serialization-avro-5.10.7-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-httpcomponents-client-4.5.4-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-httpcomponents-core-4.4.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.9.10.2-2.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jasypt-1.9.3-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaee-security-soteria-1.0.0-3.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaee-security-soteria-enterprise-1.0.0-3.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxbintros-1.0.3-1.GA_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-batch-api_1.0_spec-1.0.2-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-classfilewriter-1.2.4-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-common-beans-2.0.1-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-api_3.2_spec-1.0.2-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-client-4.0.31-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-invocation-1.5.2-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsf-api_2.3_spec-2.3.5-5.SP2_redhat_00003.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-modules-1.8.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-openjdk-orb-8.1.4-3.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-5.0.18-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-jmx-3.0.4-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-security-negotiation-3.0.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly13.0-server-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly14.0-server-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-to-eap7.2-1.3.1-10.Final_redhat_00011.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-threads-2.3.3-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-websocket-api_1.1_spec-1.1.4-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-common-3.2.3-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jgroups-4.0.20-2.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jgroups-azure-1.2.1-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jgroups-kubernetes-1.0.13-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-mod_cluster-1.4.1-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-compensations-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbosstxbridge-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbossxts-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-idlj-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-integration-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-api-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-bridge-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-integration-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-util-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-txframework-5.9.8-1.Final_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-core-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-profile-api-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-saml-api-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-saml-impl-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-security-api-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-security-impl-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-soap-api-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-api-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-impl-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-saml-api-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xacml-saml-impl-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xmlsec-api-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opensaml-xmlsec-impl-3.3.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketbox-5.0.3-7.Final_redhat_00006.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketbox-infinispan-5.0.3-7.Final_redhat_00006.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-atom-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-cdi-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-client-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-client-microprofile-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-crypto-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson2-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxb-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxrs-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jettison-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jose-jwt-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jsapi-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-binding-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-p-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-multipart-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-rxjava2-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-spring-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-validator-provider-11-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-yaml-provider-3.6.1-9.SP8_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-slf4j-jboss-logmanager-1.0.4-1.GA_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-smallrye-config-1.3.6-1.SP01_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-smallrye-health-1.0.2-2.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.0.30-2.SP2_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-cdi-2.0-api-2.0.0-4.SP1_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.2.8-3.GA_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.6.6-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.2.8-3.GA_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.2.8-3.GA_redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-naming-client-1.0.12-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-transaction-client-1.1.10-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ws-commons-XmlSchema-2.2.4-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-2.2.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-bindings-2.2.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-policy-2.2.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-common-2.2.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-dom-2.2.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-policy-stax-2.2.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wss4j-ws-security-stax-2.2.5-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-activemq-artemis / eap7-activemq-artemis-cli / etc');
}
