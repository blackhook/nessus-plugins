##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3519. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(139772);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2020-2220",
    "CVE-2020-2221",
    "CVE-2020-2222",
    "CVE-2020-2223",
    "CVE-2020-8557"
  );
  script_xref(name:"RHSA", value:"2020:3519");
  script_xref(name:"IAVA", value:"2020-A-0337-S");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.5.7 jenkins and openshift packages (RHSA-2020:3519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3519 advisory.

  - jenkins: Stored XSS vulnerability in job build time trend (CVE-2020-2220)

  - jenkins: Stored XSS vulnerability in upstream cause (CVE-2020-2221)

  - jenkins: Stored XSS vulnerability in 'keep forever' badge icons (CVE-2020-2222)

  - jenkins: Stored XSS vulnerability in console links (CVE-2020-2223)

  - kubernetes: Node disk DOS by writing to container /etc/hosts (CVE-2020-8557)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2220");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2221");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2222");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2223");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8557");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1857425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1857427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1857431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1857433");
  script_set_attribute(attribute:"solution", value:
"Update the affected jenkins and / or openshift-hyperkube packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/s390x/rhocp/4.5/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.5/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.5/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.5/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.5/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openshift-hyperkube-4.5.0-202008130146.p0.git.0.aaf1d57.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-hyperkube-4.5.0-202008130146.p0.git.0.aaf1d57.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jenkins-2.235.2.1597312414-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-hyperkube-4.5.0-202008130146.p0.git.0.aaf1d57.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
      {'reference':'openshift-hyperkube-4.5.0-202008130146.p0.git.0.aaf1d57.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
      severity   : SECURITY_NOTE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins / openshift-hyperkube');
}
