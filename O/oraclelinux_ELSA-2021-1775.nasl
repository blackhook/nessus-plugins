#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-1775.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155318);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/12");

  script_cve_id("CVE-2020-1695");

  script_name(english:"Oracle Linux 8 : pki-core:10.6 / and / pki-deps:10.6 (ELSA-2021-1775)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-1775 advisory.

  - A flaw was found in all resteasy 3.x.x versions prior to 3.12.0.Final and all resteasy 4.x.x versions
    prior to 4.6.0.Final, where an improper input validation results in returning an illegal header that
    integrates into the server's response. This flaw may result in an injection, which leads to unexpected
    behavior when the HTTP response is constructed. (CVE-2020-1695)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-1775.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bea-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-fastinfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glassfish-jaxb-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jackson-module-jaxb-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:javassist-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-acme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-servlet-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slf4j-jdk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcatjss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xml-commons-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xsom");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/pki-core');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');
if ('10.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module pki-core:' + module_ver);

var appstreams = {
    'pki-core:10.6': [
      {'reference':'apache-commons-collections-3.2.2-10.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-lang-2.6-21.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-net-3.6-3.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bea-stax-api-1.2.0-16.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-fastinfoset-1.2.13-9.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-api-2.2.12-8.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-core-2.2.11-11.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-runtime-2.2.11-11.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-txw2-2.2.11-11.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-annotations-2.10.0-1.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-core-2.10.0-1.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-databind-2.10.0-1.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-json-provider-2.9.9-1.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-providers-2.9.9-1.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-module-jaxb-annotations-2.7.6-4.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'javassist-3.18.1-8.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-javadoc-3.18.1-8.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-4.8.1-2.module+el8.4.0+20154+9830f79e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-4.8.1-2.module+el8.4.0+20154+9830f79e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-javadoc-4.8.1-2.module+el8.4.0+20154+9830f79e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-javadoc-4.8.1-2.module+el8.4.0+20154+9830f79e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-4.22.0-1.module+el8.3.0+7857+983338ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ldapjdk-javadoc-4.22.0-1.module+el8.3.0+7857+983338ee', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-acme-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-base-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-base-java-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-ca-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-kra-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-server-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-servlet-4.0-api-9.0.30-1.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'pki-servlet-engine-9.0.30-1.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'pki-symkey-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-symkey-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tools-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tools-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nss-doc-1.0.1-10.module+el8.3.0+7697+44932688', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nss-doc-1.0.1-10.module+el8.3.0+7697+44932688', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-nss-1.0.1-10.module+el8.3.0+7697+44932688', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-nss-1.0.1-10.module+el8.3.0+7697+44932688', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pki-10.10.5-2.0.1.module+el8.4.0+20154+9830f79e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'relaxngDatatype-2011.1-7.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-3.0.26-6.module+el8.4.0+20041+bb8828ef', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.25-4.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-jdk14-1.7.25-4.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'stax-ex-1.7.7-8.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'tomcatjss-7.6.1-1.module+el8.4.0+20053+7cddd5b6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'velocity-1.7-24.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-38.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xerces-j2-2.11.0-34.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-apis-1.4.01-25.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-resolver-1.2-26.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xmlstreambuffer-1.5.4-8.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xsom-0-19.20110809svn.module+el8.3.0+7697+44932688', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
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
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-collections / apache-commons-lang / apache-commons-net / etc');
}
