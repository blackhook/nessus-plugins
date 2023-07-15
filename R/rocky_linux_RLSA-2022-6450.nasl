#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:6450.
##

include('compat.inc');

if (description)
{
  script_id(167825);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-28738");
  script_xref(name:"RLSA", value:"2022:6450");

  script_name(english:"Rocky Linux 8 : ruby:3.0 (RLSA-2022:6450)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:6450 advisory.

  - A double free was found in the Regexp compiler in Ruby 3.x before 3.0.4 and 3.1.x before 3.1.2. If a
    victim attempts to create a Regexp from untrusted user input, an attacker may be able to write to
    unexpected memory locations. (CVE-2022-28738)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:6450");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bigdecimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-io-console-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-psych-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-typeprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'ruby-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debuginfo-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debuginfo-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debuginfo-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debugsource-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debugsource-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debugsource-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-default-gems-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-doc-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-debuginfo-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-debuginfo-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-debuginfo-3.0.4-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-0.4.0-1.module+el8.6.0+1001+b5678180', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-doc-0.4.0-1.module+el8.6.0+1001+b5678180', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-3.0.0-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-3.0.0-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-3.0.0-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-debuginfo-3.0.0-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-debuginfo-3.0.0-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-debuginfo-3.0.0-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bundler-2.2.33-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.5.7-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.5.7-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.5.7-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-debuginfo-0.5.7-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-debuginfo-0.5.7-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-debuginfo-0.5.7-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-irb-1.3.5-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.5.1-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.5.1-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.5.1-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-debuginfo-2.5.1-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-debuginfo-2.5.1-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-debuginfo-2.5.1-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-minitest-5.14.2-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-0.5.3-1.module+el8.6.0+1001+b5678180', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-0.5.3-1.module+el8.6.0+1001+b5678180', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debuginfo-0.5.3-1.module+el8.6.0+1001+b5678180', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debuginfo-0.5.3-1.module+el8.6.0+1001+b5678180', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debugsource-0.5.3-1.module+el8.6.0+1001+b5678180', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debugsource-0.5.3-1.module+el8.6.0+1001+b5678180', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-doc-0.5.3-1.module+el8.6.0+1001+b5678180', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-1.2.3-1.module+el8.6.0+1001+b5678180', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-1.2.3-1.module+el8.6.0+1001+b5678180', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debuginfo-1.2.3-1.module+el8.6.0+1001+b5678180', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debuginfo-1.2.3-1.module+el8.6.0+1001+b5678180', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debugsource-1.2.3-1.module+el8.6.0+1001+b5678180', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debugsource-1.2.3-1.module+el8.6.0+1001+b5678180', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-doc-1.2.3-1.module+el8.6.0+1001+b5678180', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-power_assert-1.2.0-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.3.2-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.3.2-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.3.2-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-debuginfo-3.3.2-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-debuginfo-3.3.2-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-debuginfo-3.3.2-141.module+el8.6.0+1002+a7dba0ac', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rake-13.0.3-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rbs-1.4.0-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rdoc-6.3.3-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rexml-3.2.5-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rss-0.2.9-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-test-unit-3.3.7-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-typeprof-0.15.2-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-3.2.33-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-devel-3.2.33-141.module+el8.6.0+1002+a7dba0ac', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-debuginfo / ruby-debugsource / ruby-default-gems / etc');
}
