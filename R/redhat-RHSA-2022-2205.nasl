##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:2205. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161355);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2022-29036",
    "CVE-2022-29041",
    "CVE-2022-29046",
    "CVE-2022-29047"
  );
  script_xref(name:"RHSA", value:"2022:2205");

  script_name(english:"RHEL 8 : OpenShift Container Platform 4.9.33 (RHSA-2022:2205)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2022:2205 advisory.

  - credentials: Stored XSS vulnerabilities in jenkins plugin (CVE-2022-29036)

  - Jira: Stored XSS vulnerabilities in Jenkins Jira plugin (CVE-2022-29041)

  - subversion: Stored XSS vulnerabilities in Jenkins subversion plugin (CVE-2022-29046)

  - Pipeline Shared Groovy Libraries: Untrusted users can modify some Pipeline libraries in Pipeline Shared
    Groovy Libraries Plugin (CVE-2022-29047)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29036");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29047");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:2205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074855");
  script_set_attribute(attribute:"solution", value:
"Update the affected jenkins-2-plugins package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29047");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-29046");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/rhocp/4.9/debug',
      'content/dist/layered/rhel8/aarch64/rhocp/4.9/os',
      'content/dist/layered/rhel8/aarch64/rhocp/4.9/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.9/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.9/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.9/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.9/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.9/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.9/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.9/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.9/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jenkins-2-plugins-4.9.1651754460-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins-2-plugins');
}
