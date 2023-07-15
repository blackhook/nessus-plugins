##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:0034. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145089);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2020-2304",
    "CVE-2020-2305",
    "CVE-2020-2306",
    "CVE-2020-2307",
    "CVE-2020-2308",
    "CVE-2020-2309",
    "CVE-2020-26137"
  );
  script_xref(name:"RHSA", value:"2021:0034");

  script_name(english:"RHEL 7 : OpenShift Container Platform 4.5.27 (RHSA-2021:0034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:0034 advisory.

  - jenkins-2-plugins/subversion: XML parser is not preventing XML external entity (XXE) attacks
    (CVE-2020-2304)

  - jenkins-2-plugins/mercurial: XML parser is not preventing XML external entity (XXE) attacks
    (CVE-2020-2305)

  - jenkins-2-plugins/mercurial: Missing permission check in an HTTP endpoint could result in information
    disclosure (CVE-2020-2306)

  - jenkins-2-plugins/kubernetes: Jenkins controller environment variables are accessible in Kubernetes Plugin
    (CVE-2020-2307)

  - jenkins-2-plugins/kubernetes: Missing permission check in Kubernetes Plugin allows listing pod templates
    (CVE-2020-2308)

  - jenkins-2-plugins/kubernetes: Missing permission check in Kubernetes Plugin allows enumerating credentials
    IDs (CVE-2020-2309)

  - python-urllib3: CRLF injection via HTTP request method (CVE-2020-26137)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2304");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2306");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2307");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2308");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-2309");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26137");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:0034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1883632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1895939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1895940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1895941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1895945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1895946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1895947");
  script_set_attribute(attribute:"solution", value:
"Update the affected jenkins-2-plugins and / or python2-urllib3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26137");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(113, 200, 611, 862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-urllib3");
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
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/4.1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/4.1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/4.1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.3/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.3/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.3/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.4/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.4/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.4/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.5/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.6/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.7/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.7/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/4.7/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.5/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.6/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.7/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.7/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/4.7/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.2/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.2/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.2/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.3/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.3/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.3/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.4/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.4/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.4/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.5/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.6/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.7/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.7/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ose/4.7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jenkins-2-plugins-4.5.1610108899-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-urllib3-1.26.2-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins-2-plugins / python2-urllib3');
}
