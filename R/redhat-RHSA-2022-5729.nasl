#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5729. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164871);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2022-23773",
    "CVE-2022-23806",
    "CVE-2022-24675",
    "CVE-2022-24921",
    "CVE-2022-28327",
    "CVE-2022-29526"
  );
  script_xref(name:"RHSA", value:"2022:5729");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.10.25 (RHSA-2022:5729)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:5729 advisory.

  - golang: cmd/go: misinterpretation of branch names can lead to incorrect access control (CVE-2022-23773)

  - golang: crypto/elliptic: IsOnCurve returns true for invalid field elements (CVE-2022-23806)

  - golang: encoding/pem: fix stack overflow in Decode (CVE-2022-24675)

  - golang: regexp: stack exhaustion via a deeply nested expression (CVE-2022-24921)

  - golang: crypto/elliptic: panic caused by oversized scalar (CVE-2022-28327)

  - golang: syscall: faccessat checks wrong group (CVE-2022-29526)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23773");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24675");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24921");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-28327");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29526");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2053429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2053541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2064857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2077688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2077689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2084085");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 120, 190, 252, 269, 280, 400, 863, 1220);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-service-idler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
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
      'content/dist/layered/rhel8/x86_64/rhocp/4.10/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.10/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.10/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'atomic-openshift-service-idler-4.10.0-202207192015.p0.g39cfc66.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'cri-o-1.23.3-11.rhaos4.10.gitddf4b1a.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'cri-tools-1.23.0-1.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-clients-4.10.0-202207192015.p0.g45460a5.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-clients-redistributable-4.10.0-202207192015.p0.g45460a5.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-hyperkube-4.10.0-202207192015.p0.g012e945.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.10/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.10/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.23.3-11.rhaos4.10.gitddf4b1a.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'cri-tools-1.23.0-1.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-clients-4.10.0-202207192015.p0.g45460a5.assembly.stream.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-clients-redistributable-4.10.0-202207192015.p0.g45460a5.assembly.stream.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-hyperkube-4.10.0-202207192015.p0.g012e945.assembly.stream.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'atomic-openshift-service-idler / cri-o / cri-tools / openshift-clients / etc');
}
