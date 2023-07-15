#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:0545.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158845);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/11");

  script_cve_id("CVE-2020-36327");
  script_xref(name:"ALSA", value:"2022:0545");

  script_name(english:"AlmaLinux 8 : ruby:2.5 (ALSA-2022:0545)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:0545 advisory.

  - Bundler 1.16.0 through 2.2.9 and 2.2.11 through 2.2.16 sometimes chooses a dependency source based on the
    highest gem version number, which means that a rogue gem found at a public source may be chosen, even if
    the intended choice was a private gem that is a dependency of another private gem that is explicitly
    depended on by the application. NOTE: it is not correct to use CVE-2021-24105 for every Dependency
    Confusion issue in every product. (CVE-2020-36327)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-0545.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bundler-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.5');
if ('2.5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

var appstreams = {
    'ruby:2.5': [
      {'reference':'ruby-2.5.9-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-2.5.9-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.5.9-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-2.5.9-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-2.5.9-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-irb-2.5.9-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.5.9-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-2.5.9-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-0.3.0-4.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-doc-0.3.0-4.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-1.3.4-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-1.3.4-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-4.3.0-2.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bson-doc-4.3.0-2.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-1.16.1-4.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-doc-1.16.1-4.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-did_you_mean-1.2.0-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.4.6-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.4.6-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.1.0-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.1.0-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.10.3-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-2.5.1-2.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mongo-doc-2.5.1-2.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.4.10-4.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.4.10-4.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-net-telnet-0.1.1-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-openssl-2.1.2-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.0.0-2.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.0.0-2.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-1.1.1-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.0.2-107.module_el8.5.0+2625+ec418553', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-3.0.2-107.module_el8.5.0+2625+ec418553', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-12.3.3-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.0.1.1-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.2.7-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-xmlrpc-0.3.0-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-2.7.6.3-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-2.7.6.3-107.module_el8.5.0+2625+ec418553', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach module (keys(appstreams)) {
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
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.5');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-devel / ruby-doc / ruby-irb / ruby-libs / rubygem-abrt / etc');
}
