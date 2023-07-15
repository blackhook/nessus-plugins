#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-180.
##

include('compat.inc');

if (description)
{
  script_id(176332);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2023-25652", "CVE-2023-29007");

  script_name(english:"Amazon Linux 2023 : git, git-all, git-core (ALAS2023-2023-180)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-180 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-180.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-25652.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29007.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update git --releasever 2023.0.20230517' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-29007");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-credential-libsecret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'git-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-all-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-doc-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-credential-libsecret-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-cvs-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debuginfo-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debugsource-2.40.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debugsource-2.40.1-1.amzn2023.0.1', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debugsource-2.40.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-email-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-gui-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-instaweb-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-p4-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-svn-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitk-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitweb-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-SVN-2.40.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-all / git-core / etc");
}