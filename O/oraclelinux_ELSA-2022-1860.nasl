##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-1860.
##

include('compat.inc');

if (description)
{
  script_id(161321);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-13956");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 8 : maven:3.6 (ELSA-2022-1860)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-1860 advisory.

  - Apache HttpClient versions prior to version 4.5.13 and 5.0.3 can misinterpret malformed authority
    component in request URIs passed to the library as java.net.URI object and pick the wrong target host for
    request execution. (CVE-2020-13956)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-1860.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apache-commons-lang3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cdi-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geronimo-annotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jsr-305");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-openjdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-openjdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-openjdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-shared-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:maven-wagon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-cipher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-classworlds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-containers-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-interpolation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-sec-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plexus-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sisu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slf4j");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


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

var module_ver = get_kb_item('Host/RedHat/appstream/maven');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');
if ('3.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module maven:' + module_ver);

var appstreams = {
    'maven:3.6': [
      {'reference':'aopalliance-1.0-20.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-cli-1.4-7.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-codec-1.13-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-io-2.6-6.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'apache-commons-lang3-3.9-4.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'atinject-1-31.20100611svn86.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cdi-api-2.0.1-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'geronimo-annotation-1.0-26.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'google-guice-4.2.2-4.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'guava-28.1-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpcomponents-client-4.5.10-4.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpcomponents-core-4.4.12-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jansi-1.18-4.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jcl-over-slf4j-1.7.28-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jsoup-1.12.1-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jsr-305-0-0.25.20130910svn.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-3.6.2-7.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-lib-3.6.2-7.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-openjdk11-3.6.2-7.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-openjdk17-3.6.2-7.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-openjdk8-3.6.2-7.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'maven-resolver-1.4.1-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-shared-utils-3.2.1-0.4.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'maven-wagon-3.3.4-2.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-cipher-1.7-17.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-classworlds-2.6.0-4.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-containers-component-annotations-2.1.0-2.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-interpolation-1.26-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-sec-dispatcher-1.4-29.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'plexus-utils-3.3.0-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sisu-0.3.4-2.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.28-3.module+el8.6.0+20615+edd0bff8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aopalliance / apache-commons-cli / apache-commons-codec / etc');
}
