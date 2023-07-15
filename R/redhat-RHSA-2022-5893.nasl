##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5893. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163797);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2021-44906", "CVE-2022-24823", "CVE-2022-25647");
  script_xref(name:"RHSA", value:"2022:5893");

  script_name(english:"RHEL 8 : Red Hat JBoss Enterprise Application Platform 7.4.6 Security update (Moderate) (RHSA-2022:5893)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:5893 advisory.

  - minimist: prototype pollution (CVE-2021-44906)

  - netty: world readable temporary file containing sensitive data (CVE-2022-24823)

  - com.google.code.gson-gson: Deserialization of Untrusted Data in com.google.code.gson-gson (CVE-2022-25647)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44906");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24823");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2080850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2087186");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 378, 379, 400, 502, 1321);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-gson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-el8-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-openssl-java");
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
      {'reference':'eap7-apache-cxf-3.3.13-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-rt-3.3.13-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-services-3.3.13-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-tools-3.3.13-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jsf-2.3.14-4.SP05_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-gson-2.8.9-1.redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.3.13-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.27-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.27-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-entitymanager-5.3.27-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.27-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-java8-5.3.27-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-api-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-impl-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-spi-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-api-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-impl-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-deployers-common-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-jdbc-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-validator-1.5.3-2.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.12.6.1-2.redhat_00004.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jandex-2.4.2-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-1.3.9-2.SP2_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-core-1.3.9-2.SP2_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsf-api_2.3_spec-3.0.0-5.SP06_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-5.0.25-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.10.0-18.Final_redhat_00017.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-18.Final_redhat_00017.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-18.Final_redhat_00017.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-all-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-buffer-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-dns-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-haproxy-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-http-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-http2-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-memcache-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-mqtt-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-redis-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-smtp-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-socks-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-stomp-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-codec-xml-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-common-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-handler-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-handler-proxy-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-dns-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-resolver-dns-classes-macos-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-tcnative-2.0.52-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-classes-epoll-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-classes-kqueue-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-native-epoll-4.1.77-1.Final_redhat_00001.1.el8eap', 'cpu':'x86_64', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-native-unix-common-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-rxtx-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-sctp-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-transport-udt-4.1.77-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketbox-5.0.3-10.Final_redhat_00009.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketbox-infinispan-5.0.3-10.Final_redhat_00009.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-api-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-bindings-2.5.5-26.SP12_redhat_00014.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-common-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-config-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-federation-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-idm-api-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-idm-impl-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-idm-simple-schema-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-impl-2.5.5-21.SP12_redhat_00011.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-wildfly8-2.5.5-26.SP12_redhat_00014.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.2.18-2.SP2_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.4.6-5.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.15.13-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-tool-1.15.13-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-client-common-1.1.12-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-ejb-client-1.1.12-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-naming-client-1.1.12-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-transaction-client-1.1.12-1.SP1_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.4.6-5.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.4.6-5.GA_redhat_00002.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-2.2.3-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-el8-x86_64-2.2.2-1.Final_redhat_00002.1.el8eap', 'cpu':'x86_64', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-openssl-java-2.2.3-1.Final_redhat_00001.1.el8eap', 'release':'8', 'el_string':'el8eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-apache-cxf / eap7-apache-cxf-rt / eap7-apache-cxf-services / etc');
}
