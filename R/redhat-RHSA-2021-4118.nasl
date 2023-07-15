#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:4118. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155292);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/22");

  script_cve_id(
    "CVE-2021-39240",
    "CVE-2021-39241",
    "CVE-2021-39242",
    "CVE-2021-40346"
  );
  script_xref(name:"RHSA", value:"2021:4118");
  script_xref(name:"IAVB", value:"2021-B-0056");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.9.6 packages and (RHSA-2021:4118)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:4118 advisory.

  - haproxy: does not ensure that the scheme and path portions of a URI have the expected characters
    (CVE-2021-39240)

  - haproxy: an HTTP method name may contain a space followed by the name of a protected resource
    (CVE-2021-39241)

  - haproxy: it can lead to a situation with an attacker-controlled HTTP Host header because a mismatch
    between Host and authority is mishandled (CVE-2021-39242)

  - haproxy: request smuggling attack or response splitting via duplicate content-length header
    (CVE-2021-40346)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39240");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39241");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39242");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-40346");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1995104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1995107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1995112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2000599");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40346");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 444);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-cni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ironic-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-kuryr-kubernetes");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Red Hat' >!< release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
var os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var repositories = {
    'openshift_4_9_el7': [
      'rhel-7-server-ose-4.9-debug-rpms',
      'rhel-7-server-ose-4.9-rpms',
      'rhel-7-server-ose-4.9-source-rpms'
    ],
    'openshift_4_9_el8': [
      'rhocp-4.9-for-rhel-8-aarch64-debug-rpms',
      'rhocp-4.9-for-rhel-8-aarch64-rpms',
      'rhocp-4.9-for-rhel-8-aarch64-source-rpms',
      'rhocp-4.9-for-rhel-8-s390x-debug-rpms',
      'rhocp-4.9-for-rhel-8-s390x-rpms',
      'rhocp-4.9-for-rhel-8-s390x-source-rpms',
      'rhocp-4.9-for-rhel-8-x86_64-debug-rpms',
      'rhocp-4.9-for-rhel-8-x86_64-rpms',
      'rhocp-4.9-for-rhel-8-x86_64-source-rpms'
    ]
};

var repo_sets = rhel_get_valid_repo_sets(repositories:repositories);
if(repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);
var repos_found = !(isnull(repo_sets) || isnull(max_index(keys(repo_sets))));

var constraints = [
  {
    'repo_list': ['openshift_4_9_el7'],
    'pkgs': [
      {'reference':'cri-o-1.22.0-91.rhaos4.9.gitd745cab.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'},
      {'reference':'openshift-hyperkube-4.9.0-202111020225.p0.git.d8c4430.assembly.stream.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'}
    ]
  },
  {
    'repo_list': ['openshift_4_9_el8'],
    'pkgs': [
      {'reference':'cri-o-1.22.0-78.rhaos4.9.gitd745cab.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'},
      {'reference':'openshift-hyperkube-4.9.0-202111020225.p0.git.d8c4430.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'},
      {'reference':'openshift-kuryr-cni-4.9.0-202110281423.p0.git.4595a4e.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'},
      {'reference':'openshift-kuryr-common-4.9.0-202110281423.p0.git.4595a4e.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'},
      {'reference':'openshift-kuryr-controller-4.9.0-202110281423.p0.git.4595a4e.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'},
      {'reference':'openstack-ironic-api-18.1.1-0.20211019162143.e0437cd.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift'},
      {'reference':'openstack-ironic-common-18.1.1-0.20211019162143.e0437cd.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift'},
      {'reference':'openstack-ironic-conductor-18.1.1-0.20211019162143.e0437cd.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift'},
      {'reference':'python3-ironic-tests-18.1.1-0.20211019162143.e0437cd.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift'},
      {'reference':'python3-kuryr-kubernetes-4.9.0-202110281423.p0.git.4595a4e.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift'}
    ]
  }
];

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_list = NULL;
  if (!empty_or_null(constraint_array['repo_list'])) repo_list = constraint_array['repo_list'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var release = NULL;
    var sp = NULL;
    var cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        release &&
        rhel_decide_repo_check(repo_list:repo_list, repo_sets:repo_sets) &&
        (repos_found || (!exists_check || rpm_exists(release:release, rpm:exists_check))) &&
        rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(repo_sets)) extra = rpm_report_get() + redhat_report_repo_caveat();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cri-o / openshift-hyperkube / openshift-kuryr-cni / etc');
}
