#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3291. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176320);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2021-33621", "CVE-2023-28755", "CVE-2023-28756");
  script_xref(name:"RHSA", value:"2023:3291");

  script_name(english:"RHEL 7 : rh-ruby27-ruby (RHSA-2023:3291)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:3291 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33621");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-28755");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-28756");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3291");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33621");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 113);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-racc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-ruby27-rubygems-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-ruby27-ruby-2.7.8-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-2.7.8-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-2.7.8-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-devel-2.7.8-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-devel-2.7.8-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-devel-2.7.8-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-doc-2.7.8-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-libs-2.7.8-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-libs-2.7.8-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-ruby-libs-2.7.8-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-bigdecimal-2.0.0-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-bigdecimal-2.0.0-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-bigdecimal-2.0.0-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-bundler-2.2.24-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-did_you_mean-1.4.0-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-io-console-0.5.6-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-io-console-0.5.6-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-io-console-0.5.6-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-irb-1.2.6-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-json-2.3.0-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-json-2.3.0-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-json-2.3.0-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-minitest-5.13.0-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-net-telnet-0.2.0-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-openssl-2.1.4-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-openssl-2.1.4-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-openssl-2.1.4-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-power_assert-1.1.7-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-psych-3.1.0-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-psych-3.1.0-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-psych-3.1.0-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-racc-1.4.16-132.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-racc-1.4.16-132.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-racc-1.4.16-132.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-rake-13.0.1-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-rdoc-6.2.1.1-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-test-unit-3.3.4-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygem-xmlrpc-0.3.0-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygems-3.1.6-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-ruby27-rubygems-devel-3.1.6-132.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-ruby27-ruby / rh-ruby27-ruby-devel / rh-ruby27-ruby-doc / etc');
}
