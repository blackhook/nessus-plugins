#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0924. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170353);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2019-15847");
  script_xref(name:"RHSA", value:"2020:0924");

  script_name(english:"RHEL 6 / 7 : devtoolset-8-gcc (RHSA-2020:0924)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2020:0924 advisory.

  - gcc: POWER9 DARN RNG intrinsic produces repeated output (CVE-2019-15847)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15847");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1755523");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15847");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(331);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libasan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libatomic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libgccjit-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-liblsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libtsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devtoolset-8-libubsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libasan5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liblsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libubsan1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

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
      {'reference':'devtoolset-8-gcc-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-8.3.1-3.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-c++-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-c++-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-c++-8.3.1-3.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-c++-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gdb-plugin-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gdb-plugin-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gdb-plugin-8.3.1-3.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gdb-plugin-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gfortran-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gfortran-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gfortran-8.3.1-3.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gfortran-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-plugin-devel-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-plugin-devel-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-plugin-devel-8.3.1-3.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-plugin-devel-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libasan-devel-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libatomic-devel-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-devel-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-docs-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-docs-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-docs-8.3.1-3.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-docs-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libitm-devel-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-liblsan-devel-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-liblsan-devel-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-liblsan-devel-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libquadmath-devel-8.3.1-3.2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libquadmath-devel-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libquadmath-devel-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libquadmath-devel-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-devel-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-docs-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-docs-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-docs-8.3.1-3.2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-docs-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libtsan-devel-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libtsan-devel-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libtsan-devel-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libubsan-devel-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan5-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'liblsan-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'liblsan-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'liblsan-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtsan-8.3.1-3.2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtsan-8.3.1-3.2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtsan-8.3.1-3.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libubsan1-8.3.1-3.2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'devtoolset-8-gcc-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-c++-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gdb-plugin-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-gfortran-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-gcc-plugin-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libasan-devel-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libasan-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libatomic-devel-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libatomic-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-devel-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libgccjit-docs-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libitm-devel-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libitm-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-liblsan-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libquadmath-devel-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libquadmath-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-devel-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libstdc++-docs-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libtsan-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libubsan-devel-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'devtoolset-8-libubsan-devel-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan5-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan5-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'liblsan-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtsan-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libubsan1-8.3.1-3.2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libubsan1-8.3.1-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'devtoolset-8-gcc / devtoolset-8-gcc-c++ / devtoolset-8-gcc-gdb-plugin / etc');
}
