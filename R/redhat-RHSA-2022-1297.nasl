#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1297. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159664);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2021-4104",
    "CVE-2021-44832",
    "CVE-2021-45046",
    "CVE-2021-45105",
    "CVE-2022-23302",
    "CVE-2022-23305",
    "CVE-2022-23307"
  );
  script_xref(name:"RHSA", value:"2022:1297");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"2022-A-0029");
  script_xref(name:"IAVA", value:"2022-A-0060");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/22");

  script_name(english:"RHEL 8 : Red Hat JBoss Enterprise Application Platform 7.4.4 (RHSA-2022:1297)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:1297 advisory.

  - log4j: Remote code execution in Log4j 1.x when application is configured to use JMSAppender
    (CVE-2021-4104)

  - log4j-core: remote code execution via JDBC Appender (CVE-2021-44832)

  - log4j-core: DoS in log4j 2.x with thread context message pattern and context lookup pattern (incomplete
    fix for CVE-2021-44228) (CVE-2021-45046)

  - log4j-core: DoS in log4j 2.x with Thread Context Map (MDC) input data contains a recursive lookup and
    context lookup pattern (CVE-2021-45105)

  - log4j: Remote code execution in Log4j 1.x when application is configured to use JMSSink (CVE-2022-23302)

  - log4j: SQL injection in Log4j 1.x when application is configured to use JDBCAppender (CVE-2022-23305)

  - log4j: Unsafe deserialization flaw in Chainsaw log viewer (CVE-2022-23307)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4104");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44832");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-45046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-45105");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23302");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23307");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2031667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2032580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2034067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2035951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2041949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2041959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2041967");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 89, 400, 502, 674);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ecj");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-infinispan-hibernate-cache-v53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-compensations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-idlj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-jts-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-restat-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-narayana-txframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-el8-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-yasson");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/debug',
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/os',
      'content/dist/layered/rhel8/x86_64/jbeap/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-activemq-artemis-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-cli-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-commons-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-core-client-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-dto-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-client-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-server-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-journal-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-ra-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-selector-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-server-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-service-extensions-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-tools-2.16.0-7.redhat_00034.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ecj-3.26.0-1.redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.3.9-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.25-1.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.25-1.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-entitymanager-5.3.25-1.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.25-1.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-java8-5.3.25-1.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-cachestore-jdbc-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-cachestore-remote-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-client-hotrod-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-commons-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-component-annotations-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-core-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-commons-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-spi-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-infinispan-hibernate-cache-v53-11.0.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.10.0-15.Final_redhat_00014.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-15.Final_redhat_00014.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-15.Final_redhat_00014.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-vfs-3.2.16-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-xnio-base-3.8.6-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jbossws-cxf-5.4.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-log4j-2.17.1-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-compensations-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbosstxbridge-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jbossxts-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-idlj-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-jts-integration-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-api-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-bridge-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-integration-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-restat-util-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-narayana-txframework-5.11.4-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-objectweb-asm-9.1.0-1.redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.2.16-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.4.4-3.GA_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.15.11-1.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-tool-1.15.11-1.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.4.4-3.GA_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.4.4-3.GA_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-2.2.0-3.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-el8-x86_64-2.2.0-2.Final_redhat_00002.1.el8eap', 'cpu':'x86_64', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-java-2.2.0-3.Final_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xom-1.3.7-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-yasson-1.0.10-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
