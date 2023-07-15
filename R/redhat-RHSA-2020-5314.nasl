##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5314. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145070);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2020-16012",
    "CVE-2020-26951",
    "CVE-2020-26953",
    "CVE-2020-26956",
    "CVE-2020-26958",
    "CVE-2020-26959",
    "CVE-2020-26960",
    "CVE-2020-26961",
    "CVE-2020-26965",
    "CVE-2020-26968"
  );
  script_xref(name:"RHSA", value:"2020:5314");
  script_xref(name:"IAVA", value:"2020-A-0537-S");
  script_xref(name:"IAVA", value:"2020-A-0533-S");

  script_name(english:"RHEL 8 : firefox (RHSA-2020:5314)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2020:5314 advisory.

  - Mozilla: Variable time processing of cross-origin images during drawImage calls (CVE-2020-16012)

  - Mozilla: Parsing mismatches could confuse and bypass security sanitizer for chrome privileged code
    (CVE-2020-26951)

  - Mozilla: Fullscreen could be enabled without displaying the security UI (CVE-2020-26953)

  - Mozilla: XSS through paste (manual and clipboard API) (CVE-2020-26956)

  - Mozilla: Requests intercepted through ServiceWorkers lacked MIME type restrictions (CVE-2020-26958)

  - Mozilla: Use-after-free in WebRequestService (CVE-2020-26959)

  - Mozilla: Potential use-after-free in uses of nsTArray (CVE-2020-26960)

  - Mozilla: DoH did not filter IPv4 mapped IP Addresses (CVE-2020-26961)

  - Mozilla: Software keyboards may have remembered typed passwords (CVE-2020-26965)

  - Mozilla: Memory safety bugs fixed in Firefox 83 and Firefox ESR 78.5 (CVE-2020-26968)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-16012");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26951");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26953");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26956");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26958");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26959");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26960");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26961");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26965");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26968");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1898741");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 120, 212, 354, 358, 416, 451, 829);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.0')) audit(AUDIT_OS_NOT, 'Red Hat 8.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.0/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.0/ppc64le/appstream/os',
      'content/e4s/rhel8/8.0/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.0/ppc64le/baseos/os',
      'content/e4s/rhel8/8.0/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.0/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.0/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.0/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.0/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.0/ppc64le/sap/debug',
      'content/e4s/rhel8/8.0/ppc64le/sap/os',
      'content/e4s/rhel8/8.0/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/appstream/debug',
      'content/e4s/rhel8/8.0/x86_64/appstream/os',
      'content/e4s/rhel8/8.0/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/baseos/debug',
      'content/e4s/rhel8/8.0/x86_64/baseos/os',
      'content/e4s/rhel8/8.0/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.0/x86_64/highavailability/os',
      'content/e4s/rhel8/8.0/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.0/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.0/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.0/x86_64/sap/debug',
      'content/e4s/rhel8/8.0/x86_64/sap/os',
      'content/e4s/rhel8/8.0/x86_64/sap/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'firefox-78.5.0-1.el8_0', 'sp':'0', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'firefox-78.5.0-1.el8_0', 'sp':'0', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}