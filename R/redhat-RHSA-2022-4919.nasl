##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:4919. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161910);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2020-36518",
    "CVE-2021-37136",
    "CVE-2021-37137",
    "CVE-2021-42392",
    "CVE-2021-43797",
    "CVE-2022-0084",
    "CVE-2022-0853",
    "CVE-2022-0866",
    "CVE-2022-1319",
    "CVE-2022-21299",
    "CVE-2022-21363",
    "CVE-2022-23221",
    "CVE-2022-23437",
    "CVE-2022-23913",
    "CVE-2022-24785"
  );
  script_xref(name:"RHSA", value:"2022:4919");

  script_name(english:"RHEL 8 : Red Hat JBoss Enterprise Application Platform 7.4.5 security update on RHEL 8 (Moderate) (RHSA-2022:4919)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:4919 advisory.

  - jackson-databind: denial of service via a large depth of nested objects (CVE-2020-36518)

  - netty-codec: Bzip2Decoder doesn't allow setting size restrictions for decompressed data (CVE-2021-37136)

  - netty-codec: SnappyFrameDecoder doesn't restrict chunk length and may buffer skippable chunks in an
    unnecessary way (CVE-2021-37137)

  - h2: Remote Code Execution in Console (CVE-2021-42392)

  - netty: control chars in header names may lead to HTTP request smuggling (CVE-2021-43797)

  - xnio: org.xnio.StreamConnection.notifyReadClosed log to debug instead of stderr (CVE-2022-0084)

  - jboss-client: memory leakage in remote client transaction (CVE-2022-0853)

  - wildfly: Wildfly management of EJB Session context returns wrong caller principal with Elytron Security
    enabled (CVE-2022-0866)

  - undertow: Double AJP response for 400 from EAP 7 results in CPING failures (CVE-2022-1319)

  - OpenJDK: Infinite loop related to incorrect handling of newlines in XMLEntityScanner (JAXP, 8270646)
    (CVE-2022-21299)

  - mysql-connector-java: Difficult to exploit vulnerability allows high privileged attacker with network
    access via multiple protocols to compromise MySQL Connectors (CVE-2022-21363)

  - h2: Loading of custom classes from remote servers through JNDI (CVE-2022-23221)

  - xerces-j2: infinite loop when handling specially crafted XML document payloads (CVE-2022-23437)

  - artemis-commons: Apache ActiveMQ Artemis DoS (CVE-2022-23913)

  - Moment.js: Path traversal  in moment.locale (CVE-2022-24785)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36518");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-37136");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-37137");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-42392");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43797");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0084");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0853");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0866");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1319");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21299");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21363");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23437");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23913");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24785");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:4919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2004133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2004135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2031958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2039403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2041472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2044596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2047200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2047343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2060725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2060929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2063601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2064226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2064698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2072009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2073890");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 252, 280, 400, 401, 444, 502, 770, 835, 863, 1220);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator-cdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-mqtt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-smtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-socks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-codec-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-handler-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-resolver-dns-classes-macos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-tcnative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-classes-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-classes-kqueue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-native-epoll");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-native-unix-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-rxtx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-sctp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-transport-udt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-xerces-j2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
      {'reference':'eap7-activemq-artemis-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-cli-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-commons-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-core-client-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-dto-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hornetq-protocol-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-hqclient-protocol-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jdbc-store-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-client-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-jms-server-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-journal-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-ra-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-selector-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-server-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-service-extensions-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-activemq-artemis-tools-2.16.0-9.redhat_00042.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-h2database-1.4.197-2.redhat_00004.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.3.12-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.26-1.Final_redhat_00002.2.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.26-1.Final_redhat_00002.2.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-entitymanager-5.3.26-1.Final_redhat_00002.2.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.26-1.Final_redhat_00002.2.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-java8-5.3.26-1.Final_redhat_00002.2.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-6.0.23-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-cdi-6.0.23-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-annotations-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-core-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.12.6.1-1.redhat_00003.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jdk8-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jsr310-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-base-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-json-provider-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-module-jaxb-annotations-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-base-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-java8-2.12.6-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-1.3.9-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-core-1.3.9-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsf-api_2.3_spec-3.0.0-4.SP05_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-5.0.24-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.10.0-16.Final_redhat_00015.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-16.Final_redhat_00015.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-16.Final_redhat_00015.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-xnio-base-3.8.7-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-log4j-2.17.1-2.redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-all-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-buffer-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-dns-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-haproxy-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-http-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-http2-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-memcache-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-mqtt-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-redis-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-smtp-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-socks-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-stomp-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-xml-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-common-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-handler-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-handler-proxy-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-dns-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-dns-classes-macos-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-tcnative-2.0.48-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-classes-epoll-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-classes-kqueue-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-native-epoll-4.1.72-1.Final_redhat_00001.1.el8eap', 'cpu':'x86_64', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-native-unix-common-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-rxtx-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-sctp-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-udt-4.1.72-4.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-snakeyaml-1.29.0-1.redhat_00001.2.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.2.17-2.SP4_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.4.5-3.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.15.12-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-tool-1.15.12-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-client-common-1.1.11-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-ejb-client-1.1.11-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-naming-client-1.1.11-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-transaction-client-1.1.11-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.4.5-3.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.4.5-3.GA_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-transaction-client-1.1.15-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-xerces-j2-2.12.0-3.SP04_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
