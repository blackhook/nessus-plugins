#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2023-262.
##

include('compat.inc');

if (description)
{
  script_id(170585);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/25");

  script_cve_id("CVE-2021-33621");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2023-262)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2022-2023-262 advisory.

  - The cgi gem before 0.1.0.2, 0.2.x before 0.2.2, and 0.3.x before 0.3.5 for Ruby allows HTTP response
    splitting. This is relevant to applications that use untrusted user input either to generate an HTTP
    response or to create a CGI::Cookie object. (CVE-2021-33621)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2023-262.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33621.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update ruby3.1' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-bundled-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-bundled-gems-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-bigdecimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-io-console-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-psych-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-rbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-rbs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-rexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygem-typeprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby3.1-rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ruby3.1-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-bundled-gems-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-bundled-gems-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-bundled-gems-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-bundled-gems-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-bundled-gems-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-bundled-gems-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-debugsource-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-debugsource-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-debugsource-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-default-gems-3.1.3-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-devel-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-devel-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-devel-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-doc-3.1.3-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-libs-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-libs-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-libs-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-libs-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-libs-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-libs-debuginfo-3.1.3-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-bigdecimal-3.1.1-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-bigdecimal-3.1.1-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-bigdecimal-3.1.1-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-bigdecimal-debuginfo-3.1.1-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-bigdecimal-debuginfo-3.1.1-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-bigdecimal-debuginfo-3.1.1-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-bundler-2.3.26-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-io-console-0.5.11-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-io-console-0.5.11-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-io-console-0.5.11-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-io-console-debuginfo-0.5.11-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-io-console-debuginfo-0.5.11-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-io-console-debuginfo-0.5.11-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-irb-1.4.1-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-json-2.6.1-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-json-2.6.1-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-json-2.6.1-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-json-debuginfo-2.6.1-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-json-debuginfo-2.6.1-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-json-debuginfo-2.6.1-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-minitest-5.15.0-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-power_assert-2.0.1-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-psych-4.0.4-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-psych-4.0.4-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-psych-4.0.4-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-psych-debuginfo-4.0.4-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-psych-debuginfo-4.0.4-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-psych-debuginfo-4.0.4-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rake-13.0.6-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rbs-2.7.0-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rbs-2.7.0-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rbs-2.7.0-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rbs-debuginfo-2.7.0-173.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rbs-debuginfo-2.7.0-173.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rbs-debuginfo-2.7.0-173.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rdoc-6.4.0-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rexml-3.2.5-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-rss-0.2.9-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-test-unit-3.5.3-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygem-typeprof-0.21.3-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygems-3.3.26-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby3.1-rubygems-devel-3.3.26-173.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby3.1 / ruby3.1-bundled-gems / ruby3.1-bundled-gems-debuginfo / etc");
}