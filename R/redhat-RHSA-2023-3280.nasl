#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3280. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176256);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id("CVE-2023-25652", "CVE-2023-25815", "CVE-2023-29007");
  script_xref(name:"RHSA", value:"2023:3280");

  script_name(english:"RHEL 7 : rh-git227-git (RHSA-2023:3280)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:3280 advisory.

  - Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8,
    2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, by feeding specially crafted input to `git apply --reject`, a
    path outside the working tree can be overwritten with partially controlled contents (corresponding to the
    rejected hunk(s) from the given patch). A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8,
    2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid using `git apply` with
    `--reject` when applying patches from an untrusted source. Use `git apply --stat` to inspect a patch
    before applying; avoid applying one that create a conflict where a link corresponding to the `*.rej` file
    exists. (CVE-2023-25652)

  - In Git for Windows, the Windows port of Git, no localized messages are shipped with the installer. As a
    consequence, Git is expected not to localize messages at all, and skips the gettext initialization.
    However, due to a change in MINGW-packages, the `gettext()` function's implicit initialization no longer
    uses the runtime prefix but uses the hard-coded path `C:\mingw64\share\locale` to look for localized
    messages. And since any authenticated user has the permission to create folders in `C:\` (and since
    `C:\mingw64` does not typically exist), it is possible for low-privilege users to place fake messages in
    that location where `git.exe` will pick them up in version 2.40.1. This vulnerability is relatively hard
    to exploit and requires social engineering. For example, a legitimate message at the end of a clone could
    be maliciously modified to ask the user to direct their web browser to a malicious website, and the user
    might think that the message comes from Git and is legitimate. It does require local write access by the
    attacker, though, which makes this attack vector less likely. Version 2.40.1 contains a patch for this
    issue. Some workarounds are available. Do not work on a Windows machine with shared accounts, or
    alternatively create a `C:\mingw64` folder and leave it empty. Users who have administrative rights may
    remove the permission to create folders in `C:\`. (CVE-2023-25815)

  - Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8,
    2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, a specially crafted `.gitmodules` file with submodule URLs
    that are longer than 1024 characters can used to exploit a bug in
    `config.c::git_config_copy_or_rename_section_in_file()`. This bug can be used to inject arbitrary
    configuration into a user's `$GIT_DIR/config` when attempting to remove the configuration section
    associated with that submodule. When the attacker injects configuration values which specify executables
    to run (such as `core.pager`, `core.editor`, `core.sshCommand`, etc.) this can lead to a remote code
    execution. A fix A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6,
    2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid running `git submodule deinit` on untrusted
    repositories or without prior inspection of any submodule sections in `$GIT_DIR/config`. (CVE-2023-29007)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-25652");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-25815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-29007");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3280");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-29007");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-git227-perl-Git-SVN");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
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
      {'reference':'rh-git227-git-2.27.0-6.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-2.27.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-all-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-core-2.27.0-6.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-core-2.27.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-core-doc-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-credential-libsecret-2.27.0-6.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-credential-libsecret-2.27.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-cvs-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-daemon-2.27.0-6.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-daemon-2.27.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-email-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-gui-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-instaweb-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-p4-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-subtree-2.27.0-6.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-subtree-2.27.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-git-svn-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-gitk-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-gitweb-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-perl-Git-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-git227-perl-Git-SVN-2.27.0-6.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-git227-git / rh-git227-git-all / rh-git227-git-core / etc');
}
