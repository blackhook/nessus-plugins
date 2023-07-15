#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3278. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176245);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2022-3564");
  script_xref(name:"RHSA", value:"2023:3278");

  script_name(english:"RHEL 7 : kpatch-patch (RHSA-2023:3278)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has a package installed that is affected by a vulnerability as referenced in
the RHSA-2023:3278 advisory.

  - A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the
    function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated
    identifier of this vulnerability is VDB-211087. (CVE-2022-3564)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-3564");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3278");
  script_set_attribute(attribute:"solution", value:
"Update the affected kpatch-patch-3_10_0-1062_71_1 package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3564");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:7.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-3_10_0-1062_71_1");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '7.7')) audit(AUDIT_OS_NOT, 'Red Hat 7.7', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

var kernel_live_checks = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/7/7.7/x86_64/debug',
      'content/aus/rhel/server/7/7.7/x86_64/optional/debug',
      'content/aus/rhel/server/7/7.7/x86_64/optional/os',
      'content/aus/rhel/server/7/7.7/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/7/7.7/x86_64/os',
      'content/aus/rhel/server/7/7.7/x86_64/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/highavailability/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/highavailability/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/optional/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/optional/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/optional/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap-hana/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap-hana/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap-hana/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/highavailability/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/highavailability/os',
      'content/e4s/rhel/server/7/7.7/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/optional/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/optional/os',
      'content/e4s/rhel/server/7/7.7/x86_64/optional/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/os',
      'content/e4s/rhel/server/7/7.7/x86_64/sap-hana/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/sap-hana/os',
      'content/e4s/rhel/server/7/7.7/x86_64/sap-hana/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/sap/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/sap/os',
      'content/e4s/rhel/server/7/7.7/x86_64/sap/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/source/SRPMS',
      'content/tus/rhel/server/7/7.7/x86_64/debug',
      'content/tus/rhel/server/7/7.7/x86_64/optional/debug',
      'content/tus/rhel/server/7/7.7/x86_64/optional/os',
      'content/tus/rhel/server/7/7.7/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/7/7.7/x86_64/os',
      'content/tus/rhel/server/7/7.7/x86_64/source/SRPMS'
    ],
    'kernels': {
      '3.10.0-1062.71.1.el7.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-3_10_0-1062_71_1-1-1.el7', 'sp':'7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '3.10.0-1062.71.1.el7.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-3_10_0-1062_71_1-1-1.el7', 'sp':'7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
        ]
      }
    }
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:kernel_live_checks);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
var kernel_affected = FALSE;
foreach var kernel_array ( kernel_live_checks ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(kernel_array['repo_relative_urls'])) repo_relative_urls = kernel_array['repo_relative_urls'];
  var kpatch_details = kernel_array['kernels'][uname_r];
  if (empty_or_null(kpatch_details)) continue;
  kernel_affected = TRUE;
  foreach var pkg ( kpatch_details['pkgs'] ) {
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
# No kpatch details found for the running kernel version
if (!kernel_affected) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Update Services for SAP Solutions repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get() + redhat_report_package_caveat();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpatch-patch-3_10_0-1062_71_1');
}
