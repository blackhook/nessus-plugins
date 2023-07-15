##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2779. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138023);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2019-14885", "CVE-2020-1938");
  script_xref(name:"RHSA", value:"2020:2779");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"IAVB", value:"2020-B-0010-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"RHEL 6 : Red Hat JBoss Enterprise Application Platform 6.4.23 (RHSA-2020:2779)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2779 advisory.

  - JBoss EAP: Vault system property security attribute value is revealed on CLI 'reload' command
    (CVE-2019-14885)

  - tomcat: Apache Tomcat AJP File Read/Inclusion Vulnerability (CVE-2020-1938)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14885");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1938");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1770615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1806398");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(200, 285, 532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf12-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-spi-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-deployers-common-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-jdbc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-spec-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-validator-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-core");
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
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glassfish-jsf12-eap6-1.2.15-11.b01_SP2_redhat_2.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'hornetq-2.3.25-29.SP31_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-common-api-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-common-impl-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-common-spi-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-core-api-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-core-impl-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-deployers-common-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-jdbc-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-spec-api-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'ironjacamar-validator-eap6-1.0.44-1.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbosgi-repository-2.1.0-3.Final_redhat_3.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-appclient-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-cli-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-client-all-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-clustering-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-cmp-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-configadmin-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-connector-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-controller-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-controller-client-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-core-security-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-deployment-repository-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-deployment-scanner-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-domain-http-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-domain-management-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-ee-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-ee-deployment-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-ejb3-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-embedded-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-host-controller-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jacorb-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jaxr-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jaxrs-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jdr-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jmx-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jpa-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jsf-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-jsr77-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-logging-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-mail-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-management-client-content-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-messaging-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-modcluster-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-naming-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-network-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-osgi-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-osgi-configadmin-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-osgi-service-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-picketlink-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-platform-mbean-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-pojo-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-process-controller-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-protocol-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-remoting-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-sar-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-security-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-server-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-system-jmx-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-threads-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-transactions-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-version-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-web-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-webservices-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-weld-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-as-xts-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jboss-remoting3-jmx-1.1.4-2.Final_redhat_00001.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-appclient-7.5.23-4.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-bundles-7.5.23-4.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-core-7.5.23-4.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-domain-7.5.23-4.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-javadocs-7.5.23-2.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-modules-eap-7.5.23-3.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-product-eap-7.5.23-4.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-standalone-7.5.23-4.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossas-welcome-content-eap-7.5.23-4.Final_redhat_00002.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'jbossweb-7.5.31-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'},
      {'reference':'weld-core-1.1.34-2.Final_redhat_2.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6-jboss'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glassfish-jsf12-eap6 / hornetq / ironjacamar-common-api-eap6 / etc');
}
