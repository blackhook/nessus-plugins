##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0804. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134612);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-0205",
    "CVE-2019-0210",
    "CVE-2019-10086",
    "CVE-2019-12400",
    "CVE-2019-14887",
    "CVE-2019-20444",
    "CVE-2019-20445",
    "CVE-2020-7238"
  );
  script_xref(name:"RHSA", value:"2020:0804");
  script_xref(name:"IAVA", value:"2020-A-0140");
  script_xref(name:"IAVA", value:"2020-A-0328");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"IAVA", value:"2021-A-0035-S");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 6 : Red Hat JBoss Enterprise Application Platform 7.2.7 on RHEL 6 (RHSA-2020:0804)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0804 advisory.

  - thrift: Endless loop when feed with specific input data (CVE-2019-0205)

  - thrift: Out-of-bounds read related to TJSONProtocol or TSimpleJSONProtocol (CVE-2019-0210)

  - apache-commons-beanutils: does not suppresses the class property in PropertyUtilsBean by default
    (CVE-2019-10086)

  - xml-security: Apache Santuario potentially loads XML parsing code from an untrusted source
    (CVE-2019-12400)

  - wildfly: The 'enabled-protocols' value in legacy security is not respected if OpenSSL security provider is
    in use (CVE-2019-14887)

  - netty: HTTP request smuggling (CVE-2019-20444)

  - netty: HttpObjectDecoder.java allows Content-Length header to accompanied by second Content-Length header
    (CVE-2019-20445)

  - netty: HTTP Request Smuggling due to Transfer-Encoding whitespace mishandling (CVE-2020-7238)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-0205");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-0210");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10086");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12400");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14887");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20444");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20445");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7238");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1764658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1767483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1772008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1796225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1798509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1798524");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10086");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-20445");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 125, 400, 444, 502, 757);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-el-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-v53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-istack-commons-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-istack-commons-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaegertracing-jaeger-client-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaegertracing-jaeger-client-java-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaegertracing-jaeger-client-java-thrift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-jxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jaxb-xjc");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-wildfly8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-relaxng-datatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-rngom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-stax2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-sun-istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-thrift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-linux-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-woodstox-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xml-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xsom");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
      {'reference':'eap7-activemq-artemis-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-cli-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-commons-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-core-client-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-dto-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-client-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-server-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-journal-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-ra-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-selector-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-server-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-service-extensions-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-tools-2.9.0-2.redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-commons-beanutils-1.9.4-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-codemodel-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-el-3.0.1-4.b08_redhat_00003.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-el-impl-3.0.1-4.b08_redhat_00003.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jaxb-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jsf-2.3.5-7.SP3_redhat_00005.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.0.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.15-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.15-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-entitymanager-5.3.15-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.15-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-java8-5.3.15-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-cachestore-jdbc-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-cachestore-remote-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-client-hotrod-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-commons-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-core-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-commons-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-spi-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-v53-9.3.8-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-api-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-impl-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-spi-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-api-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-impl-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-deployers-common-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-jdbc-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-validator-1.4.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-istack-commons-runtime-3.0.10-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-istack-commons-tools-3.0.10-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.9.10.2-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaegertracing-jaeger-client-java-0.34.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaegertracing-jaeger-client-java-core-0.34.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaegertracing-jaeger-client-java-thrift-0.34.1-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxb-jxc-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxb-runtime-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jaxb-xjc-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-client-4.0.28-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-5.0.17-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly13.0-server-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly14.0-server-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-to-eap7.2-1.3.1-8.Final_redhat_00009.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-bindings-2.5.5-23.SP12_redhat_00012.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-wildfly8-2.5.5-23.SP12_redhat_00012.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-relaxng-datatype-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-rngom-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-stax2-api-4.2.0-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-sun-istack-commons-3.0.10-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-thrift-0.13.0-1.redhat_00002.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-txw2-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.2.7-4.GA_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-client-common-1.0.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-ejb-client-1.0.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-naming-client-1.0.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-transaction-client-1.0.20-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.2.7-4.GA_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.2.7-4.GA_redhat_00004.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-1.0.9-2.SP03_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-java-1.0.9-2.SP03_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-linux-x86_64-1.0.9-2.SP03_redhat_00001.1.el6eap', 'cpu':'x86_64', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-transaction-client-1.1.9-1.Final_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-woodstox-core-6.0.3-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xml-security-2.1.4-1.redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xsom-2.3.3-4.b02_redhat_00001.1.el6eap', 'release':'6', 'el_string':'el6eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
