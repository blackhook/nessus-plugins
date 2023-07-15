##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5555. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163260);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_cve_id(
    "CVE-2021-3807",
    "CVE-2021-33623",
    "CVE-2021-35515",
    "CVE-2021-35516",
    "CVE-2021-35517",
    "CVE-2021-36090",
    "CVE-2022-22950",
    "CVE-2022-31051"
  );
  script_xref(name:"RHSA", value:"2022:5555");

  script_name(english:"RHEL 8 : RHV Manager (ovirt-engine) [ovirt-4.5.1] (RHSA-2022:5555)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:5555 advisory.

  - springframework: malicious input leads to insertion of additional log entries (CVE-2021-22096)

  - nodejs-trim-newlines: ReDoS in .end() method (CVE-2021-33623)

  - apache-commons-compress: infinite loop when reading a specially crafted 7Z archive (CVE-2021-35515)

  - apache-commons-compress: excessive memory allocation when reading a specially crafted 7Z archive
    (CVE-2021-35516)

  - apache-commons-compress: excessive memory allocation when reading a specially crafted TAR archive
    (CVE-2021-35517)

  - apache-commons-compress: excessive memory allocation when reading a specially crafted ZIP archive
    (CVE-2021-36090)

  - nodejs-ansi-regex: Regular expression denial of service (ReDoS) matching ANSI escape codes (CVE-2021-3807)

  - spring-expression: Denial of service via specially crafted SpEL expression (CVE-2022-22950)

  - semantic-release: Masked secrets can be disclosed if they contain characters that are excluded from uri
    encoding (CVE-2022-31051)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22096");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33623");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35515");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35516");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35517");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-36090");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-22950");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31051");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1966615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1981895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1981900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1981903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1981909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2007557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2034584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2069414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2097414");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31051");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 200, 212, 400, 770, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-compress-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-dependencies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-web-ui");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/os',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'apache-commons-compress-1.21-1.2.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'apache-commons-compress-javadoc-1.21-1.2.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-dependencies-4.5.2-1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'},
      {'reference':'ovirt-web-ui-1.9.0-1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rhevm-4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-compress / apache-commons-compress-javadoc / etc');
}
