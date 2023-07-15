##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1541. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135911);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2020-1733",
    "CVE-2020-1735",
    "CVE-2020-1737",
    "CVE-2020-1739",
    "CVE-2020-1740",
    "CVE-2020-1746",
    "CVE-2020-1753",
    "CVE-2020-10684",
    "CVE-2020-10685",
    "CVE-2020-10691"
  );
  script_xref(name:"RHSA", value:"2020:1541");
  script_xref(name:"IAVB", value:"2020-B-0016-S");
  script_xref(name:"IAVB", value:"2019-B-0092-S");

  script_name(english:"RHEL 7 / 8 : Ansible security and bug fix update (2.9.7) (Important) (RHSA-2020:1541)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1541 advisory.

  - Ansible: code injection when using ansible_facts as a subkey (CVE-2020-10684)

  - Ansible: modules which use files encrypted with vault are not properly cleaned up (CVE-2020-10685)

  - Ansible: archive traversal vulnerability in ansible-galaxy collection install (CVE-2020-10691)

  - ansible: insecure temporary directory when running become_user from become directive (CVE-2020-1733)

  - ansible: path injection on dest parameter in fetch module (CVE-2020-1735)

  - ansible: Extract-Zip function in win_unzip module does not check extracted path (CVE-2020-1737)

  - ansible: svn module leaks password when specified as a parameter (CVE-2020-1739)

  - ansible: secrets readable after ansible-vault edit (CVE-2020-1740)

  - ansible: Information disclosure issue in ldap_attr and ldap_entry modules (CVE-2020-1746)

  - Ansible: kubectl connection plugin leaks sensitive information (CVE-2020-1753)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1733");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1735");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1737");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1739");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1740");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1746");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1753");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10684");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10685");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10691");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1802193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1805491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1811008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1814627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1815519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1817161");
  script_set_attribute(attribute:"solution", value:
"Update the affected ansible and / or ansible-test packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1737");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 200, 214, 377, 459, 532, 862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/ansible/2.9/debug',
      'content/dist/layered/rhel8/aarch64/ansible/2.9/os',
      'content/dist/layered/rhel8/aarch64/ansible/2.9/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible/2.9/debug',
      'content/dist/layered/rhel8/ppc64le/ansible/2.9/os',
      'content/dist/layered/rhel8/ppc64le/ansible/2.9/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible/2.9/debug',
      'content/dist/layered/rhel8/s390x/ansible/2.9/os',
      'content/dist/layered/rhel8/s390x/ansible/2.9/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible/2.9/debug',
      'content/dist/layered/rhel8/x86_64/ansible/2.9/os',
      'content/dist/layered/rhel8/x86_64/ansible/2.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-2.9.7-1.el8ae', 'release':'8', 'el_string':'el8ae', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ansible-2.9'},
      {'reference':'ansible-test-2.9.7-1.el8ae', 'release':'8', 'el_string':'el8ae', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ansible-2.9'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ansible/2.9/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ansible/2.9/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ansible/2.9/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ansible/2.9/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ansible/2.9/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ansible/2.9/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ansible/2.9/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ansible/2.9/os',
      'content/dist/rhel/server/7/7Server/x86_64/ansible/2.9/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/ansible/2.9/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/ansible/2.9/os',
      'content/dist/rhel/system-z/7/7Server/s390x/ansible/2.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-2.9.7-1.el7ae', 'release':'7', 'el_string':'el7ae', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ansible-2.9'},
      {'reference':'ansible-test-2.9.7-1.el7ae', 'release':'7', 'el_string':'el7ae', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ansible-2.9'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible / ansible-test');
}
