##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:0247. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145405);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2020-13956",
    "CVE-2020-25633",
    "CVE-2020-25640",
    "CVE-2020-25689",
    "CVE-2020-27782",
    "CVE-2020-27822"
  );
  script_xref(name:"RHSA", value:"2021:0247");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.3.5 (RHSA-2021:0247)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:0247 advisory.

  - apache-httpclient: incorrect handling of malformed authority component in request URIs (CVE-2020-13956)

  - resteasy-client: potential sensitive information leakage in JAX-RS RESTEasy Client's
    WebApplicationException handling (CVE-2020-25633)

  - wildfly: resource adapter logs plaintext JMS password at warning level on connection error
    (CVE-2020-25640)

  - wildfly-core: memory leak in WildFly host-controller in domain mode while not able to reconnect to domain-
    controller (CVE-2020-25689)

  - undertow: special character in query results in server errors (CVE-2020-27782)

  - wildfly: Potential Memory leak in Wildfly when using OpenTracing (CVE-2020-27822)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13956");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25633");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25689");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27782");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27822");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:0247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1881637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1886587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1893070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1901304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1904060");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25633");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 209, 400, 401, 532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap6.4-to-eap7.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.2-to-eap7.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-server-migration-eap7.3-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-opentracing-interceptors");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-discovery-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-activemq-artemis-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-cli-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-commons-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-core-client-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-dto-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-client-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-server-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-journal-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-ra-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-selector-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-server-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-service-extensions-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-tools-2.9.0-7.redhat_00017.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jsf-2.3.9-12.SP13_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.2.12-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-entitymanager-5.3.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-java8-5.3.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-httpcomponents-client-4.5.13-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-client-4.0.37-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-genericjms-2.0.8-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-modules-1.11.0-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-5.0.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-to-eap7.3-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.2-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.2-to-eap7.3-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.3-server-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly13.0-server-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly14.0-server-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly15.0-server-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly16.0-server-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly17.0-server-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly18.0-server-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-1.7.2-4.Final_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-xnio-base-3.7.12-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-compensations-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbosstxbridge-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbossxts-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-idlj-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-integration-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-api-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-bridge-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-integration-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-util-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-txframework-5.9.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-opentracing-interceptors-0.0.4.1-2.redhat_00002.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-atom-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-cdi-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-client-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-client-microprofile-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-crypto-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson2-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxb-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxrs-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jettison-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jose-jwt-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jsapi-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-binding-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-p-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-multipart-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-rxjava2-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-spring-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-validator-provider-11-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-yaml-provider-3.11.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.0.33-1.SP2_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.3.5-2.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-discovery-client-1.2.1-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.10.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-tool-1.10.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-client-common-1.0.24-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-ejb-client-1.0.24-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-naming-client-1.0.24-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-transaction-client-1.0.24-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk11-7.3.5-2.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk8-7.3.5-2.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.3.5-2.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.3.5-2.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
      severity   : SECURITY_WARNING,
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
