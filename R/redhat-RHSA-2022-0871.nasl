#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:0871. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159165);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2022-0811");
  script_xref(name:"RHSA", value:"2022:0871");
  script_xref(name:"CEA-ID", value:"CEA-2022-0010");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.8.35 (RHSA-2022:0871)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:0871 advisory.

  - CRI-O: Arbitrary code execution in cri-o via abusing kernel.core_pattern kernel parameter
    (CVE-2022-0811)

  - workflow-cps: OS command execution through crafted SCM contents (CVE-2022-25173)

  - workflow-cps-global-lib: OS command execution through crafted SCM contents (CVE-2022-25174)

  - workflow-multibranch: OS command execution through crafted SCM contents (CVE-2022-25175)

  - workflow-cps: Pipeline-related plugins follow symbolic links or do not limit path names (CVE-2022-25176)

  - workflow-cps-global-lib: Pipeline-related plugins follow symbolic links or do not limit path names
    (CVE-2022-25177, CVE-2022-25178)

  - workflow-multibranch: Pipeline-related plugins follow symbolic links or do not limit path names
    (CVE-2022-25179)

  - workflow-cps: Password parameters are included from the original build in replayed builds (CVE-2022-25180)

  - workflow-cps-global-lib: Sandbox bypass vulnerability (CVE-2022-25181, CVE-2022-25182, CVE-2022-25183)

  - pipeline-build-step: Password parameter default values exposed (CVE-2022-25184)

  - credentials: Stored XSS vulnerabilities in jenkins plugin (CVE-2022-29036)

  - subversion: Stored XSS vulnerabilities in Jenkins subversion plugin (CVE-2022-29046)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25173");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25174");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25175");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25176");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25177");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25178");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25179");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25180");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25181");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25182");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25183");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25184");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29036");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:0871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2055804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2059475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074851");
  script_set_attribute(attribute:"solution", value:
"Update the affected cri-o and / or jenkins-2-plugins packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0811");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 78, 79, 94, 179, 200, 522);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/s390x/rhocp/4.8/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.8/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.8/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.8/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.8/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.21.5-3.rhaos4.8.gitaf64931.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'cri-o-1.21.5-3.rhaos4.8.gitaf64931.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'jenkins-2-plugins-4.8.1646993358-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.8/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.8/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.8/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.8/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.8/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.21.5-3.rhaos4.8.gitaf64931.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cri-o / jenkins-2-plugins');
}