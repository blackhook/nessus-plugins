#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:0611.
##

include('compat.inc');

if (description)
{
  script_id(171123);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2022-23521", "CVE-2022-41903");
  script_xref(name:"ALSA", value:"2023:0611");

  script_name(english:"AlmaLinux 9 : git (ALSA-2023:0611)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:0611 advisory.

  - Git is distributed revision control system. gitattributes are a mechanism to allow defining attributes for
    paths. These attributes can be defined by adding a `.gitattributes` file to the repository, which contains
    a set of file patterns and the attributes that should be set for paths matching this pattern. When parsing
    gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge
    number of attributes for a single pattern, or when the declared attribute names are huge. These overflows
    can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently
    splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the
    index. Consequentially, the failure mode depends on whether the file exists in the working tree, the index
    or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote
    code execution. The problem has been patched in the versions published on 2023-01-17, going back to
    v2.30.7. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-23521)

  - Git is distributed revision control system. `git log` can display commits in an arbitrary format using its
    `--format` specifiers. This functionality is also exposed to `git archive` via the `export-subst`
    gitattribute. When processing the padding operators, there is a integer overflow in
    `pretty.c::format_and_pad_commit()` where a `size_t` is stored improperly as an `int`, and then added as
    an offset to a `memcpy()`. This overflow can be triggered directly by a user running a command which
    invokes the commit formatting machinery (e.g., `git log --format=...`). It may also be triggered
    indirectly through git archive via the export-subst mechanism, which expands format specifiers inside of
    files within the repository during a git archive. This integer overflow can result in arbitrary heap
    writes, which may result in arbitrary code execution. The problem has been patched in the versions
    published on 2023-01-17, going back to v2.30.7. Users are advised to upgrade. Users who are unable to
    upgrade should disable `git archive` in untrusted repositories. If you expose git archive via `git
    daemon`, disable it by running `git config --global daemon.uploadArch false`. (CVE-2022-41903)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-0611.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(190);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

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
    {'reference':'git-2.31.1-3.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-2.31.1-3.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-all-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.31.1-3.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.31.1-3.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-doc-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.31.1-3.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.31.1-3.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.31.1-3.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.31.1-3.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-email-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-gui-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-instaweb-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.31.1-3.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.31.1-3.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-svn-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitk-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitweb-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-SVN-2.31.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
