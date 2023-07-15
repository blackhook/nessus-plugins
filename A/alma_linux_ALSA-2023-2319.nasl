#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2319.
##

include('compat.inc');

if (description)
{
  script_id(175650);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2022-24765",
    "CVE-2022-29187",
    "CVE-2022-39253",
    "CVE-2022-39260"
  );
  script_xref(name:"ALSA", value:"2023:2319");

  script_name(english:"AlmaLinux 9 : git (ALSA-2023:2319)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:2319 advisory.

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

  - Git is an open source, scalable, distributed revision control system. Versions prior to 2.30.6, 2.31.5,
    2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 are subject to exposure of sensitive information to a
    malicious actor. When performing a local clone (where the source and target of the clone are on the same
    volume), Git copies the contents of the source's `$GIT_DIR/objects` directory into the destination by
    either creating hardlinks to the source contents, or copying them (if hardlinks are disabled via `--no-
    hardlinks`). A malicious actor could convince a victim to clone a repository with a symbolic link pointing
    at sensitive information on the victim's machine. This can be done either by having the victim clone a
    malicious repository on the same machine, or having them clone a malicious repository embedded as a bare
    repository via a submodule from any source, provided they clone with the `--recurse-submodules` option.
    Git does not create symbolic links in the `$GIT_DIR/objects` directory. The problem has been patched in
    the versions published on 2022-10-18, and backported to v2.30.x. Potential workarounds: Avoid cloning
    untrusted repositories using the `--local` optimization when on a shared machine, either by passing the
    `--no-local` option to `git clone` or cloning from a URL that uses the `file://` scheme. Alternatively,
    avoid cloning repositories from untrusted sources with `--recurse-submodules` or run `git config --global
    protocol.file.allow user`. (CVE-2022-39253)

  - Git is an open source, scalable, distributed revision control system. `git shell` is a restricted login
    shell that can be used to implement Git's push/pull functionality via SSH. In versions prior to 2.30.6,
    2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4, the function that splits the command arguments
    into an array improperly uses an `int` to represent the number of entries in the array, allowing a
    malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the
    resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code
    execution on a victim machine. Note that a victim must first allow access to `git shell` as a login shell
    in order to be vulnerable to this attack. This problem is patched in versions 2.30.6, 2.31.5, 2.32.4,
    2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 and users are advised to upgrade to the latest version.
    Disabling `git shell` access via remote logins is a viable short-term workaround. (CVE-2022-39260)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-2319.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29187");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39260");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(282, 427, 59, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'git-2.39.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-2.39.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-all-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.39.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.39.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-doc-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.39.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.39.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.39.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.39.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-email-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-gui-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-instaweb-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.39.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.39.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-svn-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitk-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitweb-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-SVN-2.39.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git / git-all / git-core / git-core-doc / git-credential-libsecret / etc');
}
