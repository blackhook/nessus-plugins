#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-2584.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151450);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/07");

  script_cve_id("CVE-2020-25613", "CVE-2021-28965");

  script_name(english:"Oracle Linux 8 : ruby:2.7 (ELSA-2021-2584)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-2584 advisory.

  - An issue was discovered in Ruby through 2.5.8, 2.6.x through 2.6.6, and 2.7.x through 2.7.1. WEBrick, a
    simple HTTP server bundled with Ruby, had not checked the transfer-encoding header value rigorously. An
    attacker may potentially exploit this issue to bypass a reverse proxy (which also has a poor header
    check), which may lead to an HTTP Request Smuggling attack. (CVE-2020-25613)

  - The REXML gem before 3.2.5 in Ruby before 2.6.7, 2.7.x before 2.7.3, and 3.x before 3.0.1 does not
    properly address XML round-trip issues. An incorrect document can be produced after parsing and
    serializing. (CVE-2021-28965)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-2584.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems-devel");
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
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.7');
if ('2.7' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

appstreams = {
    'ruby:2.7': [
      {'reference':'ruby-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-default-gems-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.7.3-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-0.4.0-1.module+el8.3.0+7760+537395ec', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-doc-0.4.0-1.module+el8.3.0+7760+537395ec', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-2.0.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-2.0.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-2.0.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-4.8.1-1.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-4.8.1-1.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-doc-4.8.1-1.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-2.1.4-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.5.6-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.5.6-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.5.6-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-irb-1.2.6-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.3.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.3.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.3.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.13.0-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-2.11.3-1.module+el8.3.0+7760+537395ec', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-doc-2.11.3-1.module+el8.3.0+7760+537395ec', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.3-1.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.3-1.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.5.3-1.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-net-telnet-0.2.0-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.2.3-1.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.2.3-1.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.2.3-1.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-1.1.7-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.1.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.1.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.1.0-136.module+el8.4.0+20239+cbf59dc8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-13.0.1-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.2.1-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.3.4-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-xmlrpc-0.3.0-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-3.1.6-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-3.1.6-136.module+el8.4.0+20239+cbf59dc8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
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
      allowmaj = NULL;
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.7');

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-default-gems / ruby-devel / etc');
}
