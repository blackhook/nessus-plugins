##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:4914. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161897);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2021-3918",
    "CVE-2021-22959",
    "CVE-2021-22960",
    "CVE-2021-37701",
    "CVE-2021-37712",
    "CVE-2021-44531",
    "CVE-2021-44532",
    "CVE-2021-44533",
    "CVE-2021-44906",
    "CVE-2022-21824"
  );
  script_xref(name:"RHSA", value:"2022:4914");

  script_name(english:"RHEL 7 : rh-nodejs12-nodejs (RHSA-2022:4914)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:4914 advisory.

  - llhttp: HTTP Request Smuggling due to spaces in headers (CVE-2021-22959)

  - llhttp: HTTP Request Smuggling when parsing the body of chunked requests (CVE-2021-22960)

  - nodejs-tar: Insufficient symlink protection due to directory cache poisoning using symbolic links allowing
    arbitrary file creation and overwrite (CVE-2021-37701, CVE-2021-37712)

  - nodejs-json-schema: Prototype pollution vulnerability (CVE-2021-3918)

  - nodejs: Improper handling of URI Subject Alternative Names (CVE-2021-44531)

  - nodejs: Certificate Verification Bypass via String Injection (CVE-2021-44532)

  - nodejs: Incorrect handling of certificate subject and issuer fields (CVE-2021-44533)

  - minimist: prototype pollution (CVE-2021-44906)

  - nodejs: Prototype pollution via console.table properties (CVE-2022-21824)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3918");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22959");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22960");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-37701");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-37712");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44531");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44532");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44533");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44906");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21824");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:4914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1999731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1999739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2014057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2014059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2024702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2040839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2040846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2040856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2040862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066009");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 59, 295, 400, 444, 915, 1321);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-nodejs12-nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-nodejs12-nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-nodejs12-nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-nodejs12-npm");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-nodejs12-nodejs-12.22.12-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-nodejs-12.22.12-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-nodejs-12.22.12-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-nodejs-devel-12.22.12-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-nodejs-devel-12.22.12-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-nodejs-devel-12.22.12-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-nodejs-docs-12.22.12-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-npm-6.14.16-12.22.12.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-npm-6.14.16-12.22.12.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-nodejs12-npm-6.14.16-12.22.12.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-nodejs12-nodejs / rh-nodejs12-nodejs-devel / etc');
}
