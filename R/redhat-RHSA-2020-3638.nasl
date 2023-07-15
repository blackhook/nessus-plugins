##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3638. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(140390);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-14900",
    "CVE-2020-1695",
    "CVE-2020-1710",
    "CVE-2020-1748",
    "CVE-2020-6950",
    "CVE-2020-8840",
    "CVE-2020-9546",
    "CVE-2020-9547",
    "CVE-2020-9548",
    "CVE-2020-10672",
    "CVE-2020-10673",
    "CVE-2020-10683",
    "CVE-2020-10687",
    "CVE-2020-10693",
    "CVE-2020-10714",
    "CVE-2020-10718",
    "CVE-2020-10740",
    "CVE-2020-14297",
    "CVE-2020-14307"
  );
  script_xref(name:"RHSA", value:"2020:3638");
  script_xref(name:"IAVA", value:"2020-A-0019");
  script_xref(name:"IAVA", value:"2020-A-0326");
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"IAVA", value:"2021-A-0032");
  script_xref(name:"IAVA", value:"2021-A-0196");
  script_xref(name:"IAVA", value:"2021-A-0035-S");
  script_xref(name:"IAVA", value:"2021-A-0326");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.2.9 on RHEL 7 (RHSA-2020:3638)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3638 advisory.

  - hibernate: SQL injection issue in Hibernate ORM (CVE-2019-14900)

  - jackson-databind: mishandles the interaction between serialization gadgets and typing which could result
    in remote command execution (CVE-2020-10672, CVE-2020-10673)

  - dom4j: XML External Entity vulnerability in default SAX parser (CVE-2020-10683)

  - Undertow: Incomplete fix for CVE-2017-2666 due to permitting invalid characters in HTTP requests
    (CVE-2020-10687)

  - hibernate-validator: Improper input validation in the interpolation of constraint error messages
    (CVE-2020-10693)

  - wildfly-elytron: session fixation when using FORM authentication (CVE-2020-10714)

  - wildfly: exposed setting of TCCL via the EmbeddedManagedProcess API (CVE-2020-10718)

  - wildfly: unsafe deserialization in Wildfly Enterprise Java Beans (CVE-2020-10740)

  - wildfly: Some EJB transaction objects may get accumulated causing Denial of Service (CVE-2020-14297)

  - wildfly: EJB SessionOpenInvocations may not be removed properly after a response is received causing
    Denial of Service (CVE-2020-14307)

  - resteasy: Improper validation of response header in MediaTypeHeaderDelegate.java class (CVE-2020-1695)

  - EAP: field-name is not parsed in accordance to RFC7230 (CVE-2020-1710)

  - Wildfly: Improper authorization issue in WildFlySecurityManager when using alternative protection domain
    (CVE-2020-1748)

  - Mojarra: Path traversal via either the loc parameter or the con parameter, incomplete fix of
    CVE-2018-14371 (CVE-2020-6950)

  - jackson-databind: Lacks certain xbean-reflect/JNDI blocking (CVE-2020-8840)

  - jackson-databind: Serialization gadgets in shaded-hikari-config (CVE-2020-9546)

  - jackson-databind: Serialization gadgets in ibatis-sqlmap (CVE-2020-9547)

  - jackson-databind: Serialization gadgets in anteros-core (CVE-2020-9548)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14900");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1695");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1710");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1748");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-6950");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8840");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9546");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9547");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9548");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10672");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10673");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10683");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10687");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10693");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10714");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10718");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10740");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14297");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14307");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1666499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1694235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1785049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1793970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1805006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1805501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1807707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1815470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1815495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1825714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1828476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1834512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1851327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1853595");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 74, 89, 96, 113, 285, 384, 400, 404, 444, 502, 611, 749);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-validator-cdi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-jta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-probe-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-naming-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-http-transaction-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-transaction-client");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-dom4j-2.1.3-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jsf-2.3.5-13.SP3_redhat_00011.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.0.23-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.17-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.17-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-entitymanager-5.3.17-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.17-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-java8-5.3.17-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-6.0.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-cdi-6.0.20-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-api-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-impl-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-spi-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-api-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-impl-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-deployers-common-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-jdbc-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-validator-1.4.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.9.10.4-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-genericjms-2.0.6-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsf-api_2.3_spec-2.3.5-7.SP2_redhat_00005.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-logmanager-2.1.15-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-modules-1.8.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly13.0-server-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly14.0-server-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-to-eap7.2-1.3.1-13.Final_redhat_00014.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-xnio-base-3.7.6-4.SP3_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-atom-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-cdi-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-client-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-client-microprofile-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-crypto-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jackson2-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxb-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jaxrs-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jettison-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jose-jwt-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-jsapi-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-binding-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-json-p-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-multipart-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-rxjava2-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-spring-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-validator-provider-11-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-resteasy-yaml-provider-3.6.1-10.SP9_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.0.30-4.SP4_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-server-1.2.5-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-3.0.6-4.Final_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-impl-3.0.6-4.Final_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-jsf-3.0.6-4.Final_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-ejb-3.0.6-4.Final_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-jta-3.0.6-4.Final_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-probe-core-3.0.6-4.Final_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-web-3.0.6-4.Final_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.2.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.6.8-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-client-common-1.0.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-ejb-client-1.0.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-naming-client-1.0.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-transaction-client-1.0.22-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk11-7.2.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk8-7.2.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.2.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.2.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-transaction-client-1.1.11-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-dom4j / eap7-glassfish-jsf / eap7-hal-console / eap7-hibernate / etc');
}
