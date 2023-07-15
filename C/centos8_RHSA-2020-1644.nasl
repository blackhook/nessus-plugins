##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:1644. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146039);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2019-14540",
    "CVE-2019-16335",
    "CVE-2019-16942",
    "CVE-2019-16943",
    "CVE-2019-17531",
    "CVE-2020-10672",
    "CVE-2020-10673"
  );
  script_xref(name:"RHSA", value:"2020:1644");

  script_name(english:"CentOS 8 : pki-core:10.6 and pki-deps:10.6 (CESA-2020:1644)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:1644 advisory.

  - jackson-databind: Serialization gadgets in com.zaxxer.hikari.HikariConfig (CVE-2019-14540)

  - jackson-databind: Serialization gadgets in com.zaxxer.hikari.HikariDataSource (CVE-2019-16335)

  - jackson-databind: Serialization gadgets in org.apache.commons.dbcp.datasources.* (CVE-2019-16942)

  - jackson-databind: Serialization gadgets in com.p6spy.engine.spy.P6DataSource (CVE-2019-16943)

  - jackson-databind: Serialization gadgets in org.apache.log4j.receivers.db.* (CVE-2019-17531)

  - jackson-databind: lacks certain net.sf.ehcache blocking (CVE-2019-20330)

  - jackson-databind: mishandles the interaction between serialization gadgets and typing which could result
    in remote command execution (CVE-2020-10672, CVE-2020-10673)

  - jackson-databind: Lacks certain xbean-reflect/JNDI blocking (CVE-2020-8840)

  - jackson-databind: Serialization gadgets in shaded-hikari-config (CVE-2020-9546)

  - jackson-databind: Serialization gadgets in ibatis-sqlmap (CVE-2020-9547)

  - jackson-databind: Serialization gadgets in anteros-core (CVE-2020-9548)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1644");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16942");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bea-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glassfish-fastinfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glassfish-jaxb-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glassfish-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glassfish-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glassfish-jaxb-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:javassist-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pki-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pki-servlet-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:slf4j-jdk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcatjss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xml-commons-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xsom");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/pki-deps');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-deps:10.6');
if ('10.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module pki-deps:' + module_ver);

var appstreams = {
    'pki-deps:10.6': [
      {'reference':'apache-commons-collections-3.2.2-10.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-collections-3.2.2-10.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-lang-2.6-21.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-lang-2.6-21.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bea-stax-api-1.2.0-16.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bea-stax-api-1.2.0-16.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-fastinfoset-1.2.13-9.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-fastinfoset-1.2.13-9.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-api-2.2.12-8.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-api-2.2.12-8.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-core-2.2.11-11.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-core-2.2.11-11.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-runtime-2.2.11-11.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-runtime-2.2.11-11.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-txw2-2.2.11-11.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-txw2-2.2.11-11.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-annotations-2.10.0-1.module_el8.2.0+315+896aef55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-annotations-2.10.0-1.module_el8.2.0+315+896aef55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-core-2.10.0-1.module_el8.2.0+315+896aef55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-core-2.10.0-1.module_el8.2.0+315+896aef55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-databind-2.10.0-1.module_el8.2.0+315+896aef55', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-databind-2.10.0-1.module_el8.2.0+315+896aef55', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-json-provider-2.9.9-1.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-json-provider-2.9.9-1.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-providers-2.9.9-1.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-providers-2.9.9-1.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-module-jaxb-annotations-2.7.6-4.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-module-jaxb-annotations-2.7.6-4.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jakarta-commons-httpclient-3.1-28.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'jakarta-commons-httpclient-3.1-28.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'javassist-3.18.1-8.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-3.18.1-8.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-javadoc-3.18.1-8.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-javadoc-3.18.1-8.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-4.21.0-2.module_el8.2.0+371+f5726439', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-4.21.0-2.module_el8.2.0+371+f5726439', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-javadoc-4.21.0-2.module_el8.2.0+371+f5726439', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-javadoc-4.21.0-2.module_el8.2.0+371+f5726439', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-servlet-4.0-api-9.0.7-16.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'pki-servlet-4.0-api-9.0.7-16.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'pki-servlet-engine-9.0.7-16.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'pki-servlet-engine-9.0.7-16.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python-nss-doc-1.0.1-10.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nss-doc-1.0.1-10.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-nss-1.0.1-10.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-nss-1.0.1-10.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'relaxngDatatype-2011.1-7.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'relaxngDatatype-2011.1-7.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-3.0.26-3.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-3.0.26-3.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.25-4.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.25-4.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-jdk14-1.7.25-4.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-jdk14-1.7.25-4.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'stax-ex-1.7.7-8.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'stax-ex-1.7.7-8.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tomcatjss-7.4.1-2.module_el8.2.0+371+f5726439', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tomcatjss-7.4.1-2.module_el8.2.0+371+f5726439', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'velocity-1.7-24.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'velocity-1.7-24.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-38.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-38.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xerces-j2-2.11.0-34.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xerces-j2-2.11.0-34.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-apis-1.4.01-25.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-apis-1.4.01-25.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-resolver-1.2-26.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-resolver-1.2-26.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xmlstreambuffer-1.5.4-8.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xmlstreambuffer-1.5.4-8.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xsom-0-19.20110809svn.module_el8.1.0+233+b2be703e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xsom-0-19.20110809svn.module_el8.1.0+233+b2be703e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-deps:10.6');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-collections / apache-commons-lang / bea-stax-api / etc');
}
