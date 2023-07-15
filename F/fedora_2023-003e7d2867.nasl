#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-003e7d2867
#

include('compat.inc');

if (description)
{
  script_id(175405);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2023-25652", "CVE-2023-25815", "CVE-2023-29007");
  script_xref(name:"FEDORA", value:"2023-003e7d2867");

  script_name(english:"Fedora 36 : git (2023-003e7d2867)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-003e7d2867 advisory.

  - Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8,
    2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, by feeding specially crafted input to `git apply --reject`, a
    path outside the working tree can be overwritten with partially controlled contents (corresponding to the
    rejected hunk(s) from the given patch). A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8,
    2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid using `git apply` with
    `--reject` when applying patches from an untrusted source. Use `git apply --stat` to inspect a patch
    before applying; avoid applying one that create a conflict where a link corresponding to the `*.rej` file
    exists. (CVE-2023-25652)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-003e7d2867");
  script_set_attribute(attribute:"solution", value:
"Update the affected git package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-29007");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:git");
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
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'git-2.40.1-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git');
}
