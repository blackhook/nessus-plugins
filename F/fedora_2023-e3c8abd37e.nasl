#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-e3c8abd37e
#

include('compat.inc');

if (description)
{
  script_id(170756);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/28");

  script_cve_id("CVE-2022-24765", "CVE-2022-29187");
  script_xref(name:"FEDORA", value:"2023-e3c8abd37e");

  script_name(english:"Fedora 37 : rust-bat / rust-cargo-c / rust-exa / rust-git-delta / rust-gitui / rust-pore / rust-pretty-git-prompt / rust-rd-agent / rust-rd-hashd / rust-resctl-bench / rust-resctl-demo / rust-silver / rust-tokei (2023-e3c8abd37e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-e3c8abd37e advisory.

  - Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users
    working on multi-user machines, where untrusted parties have write access to the same hard disk. Those
    untrusted parties could create the folder `C:\.git`, which would be picked up by Git operations run
    supposedly outside a repository while searching for a Git directory. Git would then respect any config in
    said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who
    installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are
    vulnerable: simply creating a new project would already read and respect the config specified in
    `C:\.git\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The
    problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git`
    on all drives where Git commands are run, and remove read/write access from those folders as a workaround.
    Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user
    profile, e.g. `C:\Users` if the user profile is located in `C:\Users\my-user-name`. (CVE-2022-24765)

  - Git is a distributed revision control system. Git prior to versions 2.37.1, 2.36.2, 2.35.4, 2.34.4,
    2.33.4, 2.32.3, 2.31.4, and 2.30.5, is vulnerable to privilege escalation in all platforms. An
    unsuspecting user could still be affected by the issue reported in CVE-2022-24765, for example when
    navigating as root into a shared tmp directory that is owned by them, but where an attacker could create a
    git repository. Versions 2.37.1, 2.36.2, 2.35.4, 2.34.4, 2.33.4, 2.32.3, 2.31.4, and 2.30.5 contain a
    patch for this issue. The simplest way to avoid being affected by the exploit described in the example is
    to avoid running git as root (or an Administrator in Windows), and if needed to reduce its use to a
    minimum. While a generic workaround is not possible, a system could be hardened from the exploit described
    in the example by removing any such repository if it exists already and creating one as root to block any
    future attacks. (CVE-2022-29187)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-e3c8abd37e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-bat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-cargo-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-exa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-git-delta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-gitui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-pretty-git-prompt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rd-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-rd-hashd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-resctl-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-resctl-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-silver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-tokei");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'rust-bat-0.21.0-6.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-cargo-c-0.9.12-3.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-exa-0.10.1-9.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-git-delta-0.13.0-4.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gitui-0.20.1-6.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pore-0.1.8-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-pretty-git-prompt-0.2.1-15.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rd-agent-2.1.2-7.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-rd-hashd-2.1.2-7.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-resctl-bench-2.1.2-8.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-resctl-demo-2.1.2-8.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-silver-2.0.1-4.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-tokei-12.1.2-4.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rust-bat / rust-cargo-c / rust-exa / etc');
}
