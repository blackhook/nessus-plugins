#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:2431. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151290);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2020-27216",
    "CVE-2020-27218",
    "CVE-2020-27223",
    "CVE-2021-21642",
    "CVE-2021-21643",
    "CVE-2021-21644",
    "CVE-2021-21645"
  );
  script_xref(name:"RHSA", value:"2021:2431");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : OpenShift Container Platform 4.5.41 (RHSA-2021:2431)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:2431 advisory.

  - jetty: local temporary directory hijacking vulnerability (CVE-2020-27216)

  - jetty: buffer not correctly recycled in Gzip Request inflation (CVE-2020-27218)

  - jetty: request containing multiple Accept headers with a large number of quality parameters may lead to
    DoS (CVE-2020-27223)

  - jenkins-2-plugins/config-file-provider: Does not configure its XML parser to prevent XML external entity
    (XXE) attacks. (CVE-2021-21642)

  - jenkins-2-plugins/config-file-provider: Does not correctly perform permission checks in several HTTP
    endpoints. (CVE-2021-21643)

  - jenkins-2-plugins/config-file-provider: does not require POST requests for an HTTP endpoint, resulting in
    a cross-site request forgery (CSRF) vulnerability. (CVE-2021-21644)

  - jenkins-2-plugins/config-file-provider: Does not perform permission checks in several HTTP endpoints.
    (CVE-2021-21645)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27216");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27218");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27223");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21642");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21644");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21645");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1891132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1902826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1934116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1952146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1952148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1952151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1952152");
  script_set_attribute(attribute:"solution", value:
"Update the affected jenkins and / or jenkins-2-plugins packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21644");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21642");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(226, 281, 352, 377, 400, 611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jenkins-2-plugins-4.5.1623326336-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jenkins-2.277.3.1623846768-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins / jenkins-2-plugins');
}
