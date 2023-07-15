#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0552. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170909);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/01");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-10735",
    "CVE-2017-18214",
    "CVE-2018-14040",
    "CVE-2018-14041",
    "CVE-2018-14042",
    "CVE-2019-8331",
    "CVE-2019-11358",
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2022-3143",
    "CVE-2022-40149",
    "CVE-2022-40150",
    "CVE-2022-40152",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2022-45047",
    "CVE-2022-45693",
    "CVE-2022-46364"
  );
  script_xref(name:"RHSA", value:"2023:0552");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"RHEL 7 : Red Hat JBoss Enterprise Application Platform 7.4.9 Security update (Important) (RHSA-2023:0552)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:0552 advisory.

  - jquery: Cross-site scripting via cross-domain ajax requests (CVE-2015-9251)

  - bootstrap: XSS in the data-target attribute (CVE-2016-10735)

  - nodejs-moment: Regular expression denial of service (CVE-2017-18214)

  - bootstrap: Cross-site Scripting (XSS) in the collapse data-parent attribute (CVE-2018-14040)

  - bootstrap: Cross-site Scripting (XSS) in the data-target property of scrollspy (CVE-2018-14041)

  - bootstrap: Cross-site Scripting (XSS) in the data-container property of tooltip (CVE-2018-14042)

  - jquery: Prototype pollution in object's prototype leading to denial of service, remote code execution, or
    property injection (CVE-2019-11358)

  - bootstrap: XSS in the tooltip or popover data-template attribute (CVE-2019-8331)

  - jquery: Cross-site scripting due to improper injQuery.htmlPrefilter method (CVE-2020-11022)

  - jquery: Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
    (CVE-2020-11023)

  - wildfly-elytron: possible timing attacks via use of unsafe comparator (CVE-2022-3143)

  - jettison: parser crash by stackoverflow (CVE-2022-40149)

  - jettison: memory exhaustion via user-supplied XML or JSON data (CVE-2022-40150)

  - woodstox-core: woodstox to serialise XML data was vulnerable to Denial of Service attacks (CVE-2022-40152)

  - jackson-databind: deep wrapper array nesting wrt UNWRAP_SINGLE_VALUE_ARRAYS (CVE-2022-42003)

  - jackson-databind: use of deeply nested arrays (CVE-2022-42004)

  - mina-sshd: Java unsafe deserialization vulnerability (CVE-2022-45047)

  - jettison:  If the value in map is the map's self, the new new JSONObject(map) cause StackOverflowError
    which may lead to dos (CVE-2022-45693)

  - Apache CXF: SSRF Vulnerability (CVE-2022-46364)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2015-9251");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2016-10735");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18214");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8331");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11358");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11022");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11023");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-3143");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-40149");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-40150");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-40152");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-42003");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-42004");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-45047");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-45693");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-46364");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1399546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1553413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1601614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1601616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1601617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1668097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1686454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1701972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1828406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1850004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2124682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2134291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2135244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2135247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2135770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2135771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2145194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2155682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2155970");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46364");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 121, 208, 400, 502, 787, 918);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-apache-sshd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hal-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-backend-jms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-orm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-hibernate-search-serialization-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-ironjacamar-validator");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaee-security-soteria");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-javaee-security-soteria-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-undertow-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-elytron-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-java-jdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-wildfly-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-woodstox-core");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-apache-sshd-2.9.2-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hal-console-3.3.16-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-5.10.13-3.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-backend-jgroups-5.10.13-3.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-backend-jms-5.10.13-3.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-engine-5.10.13-3.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-orm-5.10.13-3.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-hibernate-search-serialization-avro-5.10.13-3.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-api-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-impl-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-common-spi-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-api-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-core-impl-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-deployers-common-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-jdbc-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-ironjacamar-validator-1.5.10-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-annotations-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-core-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-databind-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jdk8-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-datatype-jsr310-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-base-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-jaxrs-json-provider-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-module-jaxb-annotations-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-base-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jackson-modules-java8-2.12.7-1.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaee-security-soteria-1.0.1-3.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-javaee-security-soteria-enterprise-1.0.1-3.redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-ejb-client-4.0.49-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsf-api_2.3_spec-3.0.0-6.SP07_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-jsp-api_2.3_spec-2.0.0-3.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-remoting-5.0.27-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-1.10.0-24.Final_redhat_00023.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-cli-1.10.0-24.Final_redhat_00023.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jboss-server-migration-core-1.10.0-24.Final_redhat_00023.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-jettison-1.5.2-1.redhat_00002.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-2.2.22-1.SP3_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-undertow-server-1.9.3-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-7.4.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-1.15.16-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-elytron-tool-1.15.16-1.Final_redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk11-7.4.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-java-jdk8-7.4.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-javadocs-7.4.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-wildfly-modules-7.4.9-4.GA_redhat_00003.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'},
      {'reference':'eap7-woodstox-core-6.4.0-1.redhat_00001.1.el7eap', 'release':'7', 'el_string':'el7eap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7-jboss'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-apache-sshd / eap7-hal-console / eap7-hibernate-search / etc');
}
