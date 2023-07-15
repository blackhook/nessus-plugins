#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1102. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172226);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2022-21594",
    "CVE-2022-21599",
    "CVE-2022-21604",
    "CVE-2022-21608",
    "CVE-2022-21611",
    "CVE-2022-21617",
    "CVE-2022-21625",
    "CVE-2022-21632",
    "CVE-2022-21633",
    "CVE-2022-21637",
    "CVE-2022-21640",
    "CVE-2022-39400",
    "CVE-2022-39408",
    "CVE-2022-39410",
    "CVE-2023-21836",
    "CVE-2023-21863",
    "CVE-2023-21864",
    "CVE-2023-21865",
    "CVE-2023-21867",
    "CVE-2023-21868",
    "CVE-2023-21869",
    "CVE-2023-21870",
    "CVE-2023-21871",
    "CVE-2023-21873",
    "CVE-2023-21874",
    "CVE-2023-21875",
    "CVE-2023-21876",
    "CVE-2023-21877",
    "CVE-2023-21878",
    "CVE-2023-21879",
    "CVE-2023-21880",
    "CVE-2023-21881",
    "CVE-2023-21882",
    "CVE-2023-21883",
    "CVE-2023-21887"
  );
  script_xref(name:"IAVA", value:"2023-A-0043");
  script_xref(name:"RHSA", value:"2023:1102");

  script_name(english:"RHEL 7 : rh-mysql80-mysql (RHSA-2023:1102)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:1102 advisory.

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21594, CVE-2022-21608,
    CVE-2022-21625, CVE-2022-21640, CVE-2022-39400, CVE-2022-39408, CVE-2022-39410)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Oct 2022) (CVE-2022-21599)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21604, CVE-2022-21611, CVE-2022-21637)

  - mysql: Server: Connection Handling unspecified vulnerability (CPU Oct 2022) (CVE-2022-21617)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Oct 2022) (CVE-2022-21632)

  - mysql: Server: Replication unspecified vulnerability (CPU Oct 2022) (CVE-2022-21633)

  - mysql: Server: DML unspecified vulnerability (CPU Jan 2023) (CVE-2023-21836)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21863, CVE-2023-21864,
    CVE-2023-21865, CVE-2023-21867, CVE-2023-21868, CVE-2023-21870, CVE-2023-21873, CVE-2023-21876,
    CVE-2023-21878, CVE-2023-21879, CVE-2023-21881, CVE-2023-21882, CVE-2023-21883)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21869, CVE-2023-21871, CVE-2023-21877,
    CVE-2023-21880)

  - mysql: Server: Thread Pooling unspecified vulnerability (CPU Jan 2023) (CVE-2023-21874)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Jan 2023) (CVE-2023-21875)

  - mysql: Server: GIS unspecified vulnerability (CPU Jan 2023) (CVE-2023-21887)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21594");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21599");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21604");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21608");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21611");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21617");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21625");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21633");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21637");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39400");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39408");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39410");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21836");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21863");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21864");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21865");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21867");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21868");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21869");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21870");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21871");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21873");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21874");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21875");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21876");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21877");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21878");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21879");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21880");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21881");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21882");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21883");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21887");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162291");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21880");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21875");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-config-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-icu-data-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'rh-mysql80-mysql-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-icu-data-files-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-icu-data-files-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-icu-data-files-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.32-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.32-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.32-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mysql80-mysql / rh-mysql80-mysql-common / rh-mysql80-mysql-config / etc');
}
