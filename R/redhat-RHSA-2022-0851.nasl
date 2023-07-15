#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:0851. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158923);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2021-0920",
    "CVE-2021-4028",
    "CVE-2021-4083",
    "CVE-2022-0330",
    "CVE-2022-0492",
    "CVE-2022-22942"
  );
  script_xref(name:"RHSA", value:"2022:0851");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"RHEL 8 : kpatch-patch (RHSA-2022:0851)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:0851 advisory.

  - kernel: Use After Free in unix_gc() which could result in a local privilege escalation (CVE-2021-0920)

  - kernel: use-after-free in RDMA listen() (CVE-2021-4028)

  - kernel: fget: check that the fd still exists after getting a ref to it (CVE-2021-4083)

  - kernel: possible privileges escalation due to missing TLB flush (CVE-2022-0330)

  - kernel: cgroups v1 release_agent feature may allow privilege escalation (CVE-2022-0492)

  - kernel: failing usercopy allows for use-after-free exploitation (CVE-2022-22942)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-0920");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4028");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4083");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0330");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-22942");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:0851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2027201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2029923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2031930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2042404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2044809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2051505");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(281, 287, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_44_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_48_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_51_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_51_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_52_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_54_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_56_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_57_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-4_18_0-147_59_1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.1')) audit(AUDIT_OS_NOT, 'Red Hat 8.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

var kernel_live_checks = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.1/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.1/ppc64le/appstream/os',
      'content/e4s/rhel8/8.1/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.1/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.1/ppc64le/baseos/os',
      'content/e4s/rhel8/8.1/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.1/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.1/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.1/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.1/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.1/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.1/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.1/ppc64le/sap/debug',
      'content/e4s/rhel8/8.1/ppc64le/sap/os',
      'content/e4s/rhel8/8.1/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/appstream/debug',
      'content/e4s/rhel8/8.1/x86_64/appstream/os',
      'content/e4s/rhel8/8.1/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/baseos/debug',
      'content/e4s/rhel8/8.1/x86_64/baseos/os',
      'content/e4s/rhel8/8.1/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.1/x86_64/highavailability/os',
      'content/e4s/rhel8/8.1/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.1/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.1/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/sap/debug',
      'content/e4s/rhel8/8.1/x86_64/sap/os',
      'content/e4s/rhel8/8.1/x86_64/sap/source/SRPMS'
    ],
    'kernels': {
      '4.18.0-147.44.1.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_44_1-1-10.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.44.1.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_44_1-1-10.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.48.1.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_48_1-1-7.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.48.1.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_48_1-1-7.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.51.1.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_51_1-1-6.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.51.1.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_51_1-1-6.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.51.2.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_51_2-1-5.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.51.2.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_51_2-1-5.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.52.1.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_52_1-1-4.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.52.1.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_52_1-1-4.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.54.2.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_54_2-1-3.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.54.2.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_54_2-1-3.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.56.1.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_56_1-1-3.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.56.1.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_56_1-1-3.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.57.1.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_57_1-1-2.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.57.1.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_57_1-1-2.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.59.1.el8_1.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_59_1-1-1.el8_1', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '4.18.0-147.59.1.el8_1.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-4_18_0-147_59_1-1-1.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpatch-patch-4_18_0-147_44_1 / kpatch-patch-4_18_0-147_48_1 / etc');
}
