##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0160. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(133157);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2019-10219",
    "CVE-2019-14540",
    "CVE-2019-14885",
    "CVE-2019-14888",
    "CVE-2019-14892",
    "CVE-2019-14893",
    "CVE-2019-16335",
    "CVE-2019-16869",
    "CVE-2019-16942",
    "CVE-2019-16943",
    "CVE-2019-17267",
    "CVE-2019-17531"
  );
  script_xref(name:"RHSA", value:"2020:0160");
  script_xref(name:"IAVA", value:"2020-A-0140");
  script_xref(name:"IAVA", value:"2020-A-0328");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.2.6 on RHEL 7 (RHSA-2020:0160)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:0160 advisory.

  - hibernate-validator: safeHTML validator allows XSS (CVE-2019-10219)

  - jackson-databind: Serialization gadgets in com.zaxxer.hikari.HikariConfig (CVE-2019-14540)

  - JBoss EAP: Vault system property security attribute value is revealed on CLI 'reload' command
    (CVE-2019-14885)

  - undertow: possible Denial Of Service (DOS) in Undertow HTTP server listening on HTTPS (CVE-2019-14888)

  - jackson-databind: Serialization gadgets in classes of the commons-configuration package (CVE-2019-14892)

  - jackson-databind: Serialization gadgets in classes of the xalan package (CVE-2019-14893)

  - jackson-databind: Serialization gadgets in com.zaxxer.hikari.HikariDataSource (CVE-2019-16335)

  - netty: HTTP request smuggling by mishandled whitespace before the colon in HTTP headers (CVE-2019-16869)

  - jackson-databind: Serialization gadgets in org.apache.commons.dbcp.datasources.* (CVE-2019-16942)

  - jackson-databind: Serialization gadgets in com.p6spy.engine.spy.P6DataSource (CVE-2019-16943)

  - jackson-databind: Serialization gadgets in classes of the ehcache package (CVE-2019-17267)

  - jackson-databind: Serialization gadgets in org.apache.log4j.receivers.db.* (CVE-2019-17531)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10219");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14540");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14885");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14888");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14892");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16335");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16869");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16942");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16943");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17267");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17531");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1738673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1755831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1755849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1758619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1770615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1772464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1775293");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17267");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 200, 400, 444, 502, 532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-cxf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-glassfish-jsf");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-dataformats-binary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-dataformats-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-datatype-jsr310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jackson-modules-java8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jberet-core");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-netty-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-picketlink-wildfly8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-jastow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-core-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-jta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-probe-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-weld-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
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
      {'reference':'eap7-apache-cxf-3.2.11-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-rt-3.2.11-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-services-3.2.11-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-apache-cxf-tools-3.2.11-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-glassfish-jsf-2.3.5-6.SP3_redhat_00004.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.0.19-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-5.3.14-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-core-5.3.14-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-entitymanager-5.3.14-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-envers-5.3.14-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-java8-5.3.14-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-6.0.18-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-validator-cdi-6.0.18-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-annotations-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-core-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.9.10.1-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-dataformats-binary-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-dataformats-text-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jdk8-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jsr310-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-base-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-json-provider-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-module-jaxb-annotations-2.9.10-2.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-base-2.9.10-2.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-java8-2.9.10-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-1.3.5-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jberet-core-1.3.5-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-client-4.0.27-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsf-api_2.3_spec-2.3.5-3.SP2_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap6.4-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.0-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.1-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.0-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly10.1-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly11.0-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly12.0-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly13.0-server-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly14.0-server-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly8.2-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-wildfly9.0-to-eap7.2-1.3.1-7.Final_redhat_00007.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-xnio-base-3.7.6-3.SP2_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-4.1.42-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-netty-all-4.1.42-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-bindings-2.5.5-21.SP12_redhat_00010.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-picketlink-wildfly8-2.5.5-21.SP12_redhat_00010.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.0.28-2.SP1_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-jastow-2.0.8-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-3.0.6-3.Final_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-impl-3.0.6-3.Final_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-core-jsf-3.0.6-3.Final_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-ejb-3.0.6-3.Final_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-jta-3.0.6-3.Final_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-probe-core-3.0.6-3.Final_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-weld-web-3.0.6-3.Final_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.2.6-5.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-client-common-1.0.18-2.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-ejb-client-1.0.18-2.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-naming-client-1.0.18-2.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-http-transaction-client-1.0.18-2.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk11-7.2.6-5.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk8-7.2.6-5.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.2.6-5.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.2.6-5.GA_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-transaction-client-1.1.8-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
