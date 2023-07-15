#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:3821.
##

include('compat.inc');

if (description)
{
  script_id(177779);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/01");

  script_cve_id("CVE-2021-33621", "CVE-2023-28755", "CVE-2023-28756");
  script_xref(name:"ALSA", value:"2023:3821");

  script_name(english:"AlmaLinux 8 : ruby:2.7 (ALSA-2023:3821)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:3821 advisory.

  - The cgi gem before 0.1.0.2, 0.2.x before 0.2.2, and 0.3.x before 0.3.5 for Ruby allows HTTP response
    splitting. This is relevant to applications that use untrusted user input either to generate an HTTP
    response or to create a CGI::Cookie object. (CVE-2021-33621)

  - A ReDoS issue was discovered in the URI component through 0.12.0 in Ruby through 3.2.1. The URI parser
    mishandles invalid URLs that have specific characters. It causes an increase in execution time for parsing
    strings to URI objects. The fixed versions are 0.12.1, 0.11.1, 0.10.2 and 0.10.0.1. (CVE-2023-28755)

  - A ReDoS issue was discovered in the Time component through 0.2.1 in Ruby through 3.2.1. The Time parser
    mishandles invalid URLs that have specific characters. It causes an increase in execution time for parsing
    strings to Time objects. The fixed versions are 0.1.1 and 0.2.2. (CVE-2023-28756)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-3821.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33621");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(113, 20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.7');
if ('2.7' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

var appstreams = {
    'ruby:2.7': [
      {'reference':'ruby-2.7.8-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-default-gems-2.7.8-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.7.8-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-2.7.8-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.7.8-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-0.4.0-1.module_el8.5.0+2595+0c654ebc', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-doc-0.4.0-1.module_el8.5.0+2595+0c654ebc', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-2.0.0-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-4.8.1-1.module_el8.3.0+6147+d0dfc1e4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-4.8.1-1.module_el8.3.0+6147+d0dfc1e4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-doc-4.8.1-1.module_el8.3.0+6147+d0dfc1e4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-2.2.24-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.5.6-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-irb-1.2.6-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.3.0-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.13.0-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-2.11.3-1.module_el8.3.0+6147+d0dfc1e4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-doc-2.11.3-1.module_el8.3.0+6147+d0dfc1e4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.3-1.module_el8.5.0+2595+0c654ebc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.3-1.module_el8.5.0+2595+0c654ebc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.5.3-1.module_el8.5.0+2595+0c654ebc', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-net-telnet-0.2.0-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.4-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.2.3-1.module_el8.5.0+2595+0c654ebc', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.2.3-1.module_el8.5.0+2595+0c654ebc', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.2.3-1.module_el8.5.0+2595+0c654ebc', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-1.1.7-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.1.0-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-13.0.1-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.2.1.1-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.3.4-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-xmlrpc-0.3.0-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-3.1.6-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-3.1.6-139.module_el8.8.0+3578+2b4b06da', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.7');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-default-gems / ruby-devel / ruby-doc / ruby-libs / etc');
}
