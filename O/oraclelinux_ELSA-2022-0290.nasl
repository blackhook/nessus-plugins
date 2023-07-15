#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-0290.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157159);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2021-4104",
    "CVE-2022-23302",
    "CVE-2022-23305",
    "CVE-2022-23307"
  );
  script_xref(name:"IAVA", value:"0001-A-0650");
  script_xref(name:"IAVA", value:"2021-A-0573");

  script_name(english:"Oracle Linux 8 : parfait:0.5 (ELSA-2022-0290)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-0290 advisory.

  - JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker
    has write access to the Log4j configuration or if the configuration references an LDAP service the
    attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing
    JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to
    CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which
    is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2
    as it addresses numerous other issues from the previous versions. (CVE-2022-23302)

  - By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the
    values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be
    included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or
    headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue
    only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default.
    Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized
    SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2022-23305)

  - CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chainsaw
    V2.0 Chainsaw was a component of Apache Log4j 1.2.x where the same issue exists. (CVE-2022-23307)

  - JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write
    access to the Log4j configuration. The attacker can provide TopicBindingName and
    TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result
    in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2
    when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2021-4104)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-0290.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:parfait");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:parfait-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:parfait-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pcp-parfait-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:si-units");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:si-units-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:unit-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:unit-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uom-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uom-lib-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uom-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uom-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uom-se-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uom-systems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uom-systems-javadoc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/parfait');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module parfait:0.5');
if ('0.5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module parfait:' + module_ver);

var appstreams = {
    'parfait:0.5': [
      {'reference':'parfait-0.5.4-4.module+el8.5.0+20480+407d1823', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'parfait-examples-0.5.4-4.module+el8.5.0+20480+407d1823', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'parfait-javadoc-0.5.4-4.module+el8.5.0+20480+407d1823', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pcp-parfait-agent-0.5.4-4.module+el8.5.0+20480+407d1823', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'si-units-0.6.5-2.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'si-units-javadoc-0.6.5-2.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'unit-api-1.0-5.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'unit-api-javadoc-1.0-5.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-lib-1.0.1-6.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-lib-javadoc-1.0.1-6.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-parent-1.0.3-3.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-se-1.0.4-3.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-se-javadoc-1.0.4-3.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-systems-0.7-1.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'uom-systems-javadoc-0.7-1.module+el8+5163+abb6ece5', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module parfait:0.5');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'parfait / parfait-examples / parfait-javadoc / etc');
}
