##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2605. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(137563);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2020-11612");
  script_xref(name:"RHSA", value:"2020:2605");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 6 / 8 : AMQ Clients 2.7.0 Release (Low) (RHSA-2020:2605)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 8 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2020:2605 advisory.

  - netty: compression/decompression codecs don't enforce limits on buffer allocation sizes (CVE-2020-11612)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11612");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816216");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-rhea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-cpp-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-qpid_proton");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','8'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/amq/2.9/debug',
      'content/dist/layered/rhel8/x86_64/amq/2.9/os',
      'content/dist/layered/rhel8/x86_64/amq/2.9/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/amq/2/debug',
      'content/dist/layered/rhel8/x86_64/amq/2/os',
      'content/dist/layered/rhel8/x86_64/amq/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'nodejs-rhea-1.0.21-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-qpid-proton-docs-0.31.0-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qpid-proton-0.31.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-1.39.0-5.el8amq', 'cpu':'x86_64', 'release':'8', 'el_string':'el8amq', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-devel-1.39.0-5.el8amq', 'cpu':'x86_64', 'release':'8', 'el_string':'el8amq', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-docs-1.39.0-5.el8amq', 'release':'8', 'el_string':'el8amq', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-0.31.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-devel-0.31.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-docs-0.31.0-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-0.31.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-devel-0.31.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-docs-0.31.0-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-tests-0.31.0-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-qpid_proton-0.31.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/amq/2/debug',
      'content/dist/rhel/client/6/6Client/i386/amq/2/os',
      'content/dist/rhel/client/6/6Client/i386/amq/2/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/amq/2/debug',
      'content/dist/rhel/client/6/6Client/x86_64/amq/2/os',
      'content/dist/rhel/client/6/6Client/x86_64/amq/2/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/amq/2/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/amq/2/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/amq/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/amq/2/debug',
      'content/dist/rhel/server/6/6Server/i386/amq/2/os',
      'content/dist/rhel/server/6/6Server/i386/amq/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/amq/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/amq/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/amq/2/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/amq/2/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/amq/2/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/amq/2/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/amq/2/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/amq/2/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/amq/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qpid-proton-0.31.0-3.el6_10', 'cpu':'i686', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-qpid-proton-0.31.0-3.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-qpid-proton-docs-0.31.0-3.el6_10', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-1.36.0-30.el6_10amq', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10amq', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-devel-1.36.0-30.el6_10amq', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10amq', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-docs-1.36.0-30.el6_10amq', 'release':'6', 'el_string':'el6_10amq', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-0.31.0-3.el6_10', 'cpu':'i686', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-0.31.0-3.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-devel-0.31.0-3.el6_10', 'cpu':'i686', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-devel-0.31.0-3.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-docs-0.31.0-3.el6_10', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-0.31.0-3.el6_10', 'cpu':'i686', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-0.31.0-3.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-devel-0.31.0-3.el6_10', 'cpu':'i686', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-devel-0.31.0-3.el6_10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-docs-0.31.0-3.el6_10', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-tests-0.31.0-3.el6_10', 'release':'6', 'el_string':'el6_10', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs-rhea / python-qpid-proton / python-qpid-proton-docs / etc');
}
