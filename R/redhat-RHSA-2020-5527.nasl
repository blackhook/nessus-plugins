##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5527. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144379);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2020-27826");
  script_xref(name:"RHSA", value:"2020:5527");

  script_name(english:"RHEL 7 : Red Hat Single Sign-On 7.4.4 security update on RHEL 7 (Low) (RHSA-2020:5527)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:5527 advisory.

  - keycloak: Account REST API can update user metadata attributes (CVE-2020-27826)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27826");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1905089");
  script_set_attribute(attribute:"solution", value:
"Update the affected rh-sso7-keycloak and / or rh-sso7-keycloak-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-sso7-keycloak-server");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.5/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.5/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.5/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.6/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.6/os',
      'content/dist/rhel/server/7/7Server/x86_64/rh-sso/7.6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-sso7-keycloak-9.0.10-1.redhat_00001.1.el7sso', 'release':'7', 'el_string':'el7sso', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rh-sso'},
      {'reference':'rh-sso7-keycloak-server-9.0.10-1.redhat_00001.1.el7sso', 'release':'7', 'el_string':'el7sso', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rh-sso'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-sso7-keycloak / rh-sso7-keycloak-server');
}
