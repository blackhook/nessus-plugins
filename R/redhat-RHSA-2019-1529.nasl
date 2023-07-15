#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1529. The text
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126030);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id(
    "CVE-2018-8014",
    "CVE-2018-8034",
    "CVE-2018-8037",
    "CVE-2018-11784"
  );
  script_xref(name:"RHSA", value:"2019:1529");

  script_name(english:"RHEL 8 : pki-deps:10.6 (RHSA-2019:1529)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for the pki-deps:10.6 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Public Key Infrastructure (PKI) Deps module contains fundamental
packages required as dependencies for the pki-core module by Red Hat
Certificate System.

Security Fix(es) :

* tomcat: Due to a mishandling of close in NIO/NIO2 connectors user
sessions can get mixed up (CVE-2018-8037)

* tomcat: Insecure defaults in CORS filter enable
'supportsCredentials' for all origins (CVE-2018-8014)

* tomcat: Open redirect in default servlet (CVE-2018-11784)

* tomcat: Host name verification missing in WebSocket client
(CVE-2018-8034)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1529");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-8014");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-8034");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-8037");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-11784");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8014");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bea-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-fastinfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-servlet-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jdk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xsom");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/pki-deps');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-deps:10.6');
if ('10.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module pki-deps:' + module_ver);

appstreams = {
    'pki-deps:10.6': [
      {'reference':'apache-commons-collections-3.2.2-10.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'apache-commons-lang-2.6-21.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'bea-stax-api-1.2.0-16.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'glassfish-fastinfoset-1.2.13-9.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'glassfish-jaxb-api-2.2.12-8.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'glassfish-jaxb-core-2.2.11-11.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'glassfish-jaxb-runtime-2.2.11-11.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'glassfish-jaxb-txw2-2.2.11-11.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'jackson-annotations-2.9.8-1.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'jackson-core-2.9.8-1.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'jackson-databind-2.9.8-1.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'jackson-jaxrs-json-provider-2.9.8-1.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'jackson-jaxrs-providers-2.9.8-1.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'jackson-module-jaxb-annotations-2.7.6-4.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.0.0+3248+9d514f3b', 'release':'8', 'epoch':'1'},
      {'reference':'javassist-3.18.1-8.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'javassist-javadoc-3.18.1-8.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'pki-servlet-4.0-api-9.0.7-14.module+el8.0.0+3248+9d514f3b', 'release':'8', 'epoch':'1'},
      {'reference':'pki-servlet-container-9.0.7-14.module+el8.0.0+3248+9d514f3b', 'release':'8', 'epoch':'1'},
      {'reference':'python-nss-debugsource-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'aarch64', 'release':'8'},
      {'reference':'python-nss-debugsource-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'s390x', 'release':'8'},
      {'reference':'python-nss-debugsource-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'x86_64', 'release':'8'},
      {'reference':'python-nss-doc-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'aarch64', 'release':'8'},
      {'reference':'python-nss-doc-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'s390x', 'release':'8'},
      {'reference':'python-nss-doc-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'x86_64', 'release':'8'},
      {'reference':'python3-nss-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'aarch64', 'release':'8'},
      {'reference':'python3-nss-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'s390x', 'release':'8'},
      {'reference':'python3-nss-1.0.1-10.module+el8.0.0+3248+9d514f3b', 'cpu':'x86_64', 'release':'8'},
      {'reference':'relaxngDatatype-2011.1-7.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'resteasy-3.0.26-3.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'slf4j-1.7.25-4.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'slf4j-jdk14-1.7.25-4.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'stax-ex-1.7.7-8.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'velocity-1.7-24.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'xalan-j2-2.7.1-38.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'xerces-j2-2.11.0-34.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'xml-commons-apis-1.4.01-25.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'xml-commons-resolver-1.2-26.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'xmlstreambuffer-1.5.4-8.module+el8.0.0+3248+9d514f3b', 'release':'8'},
      {'reference':'xsom-0-19.20110809svn.module+el8.0.0+3248+9d514f3b', 'release':'8'}
    ],
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'RHEL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-collections / apache-commons-lang / bea-stax-api / etc');
}