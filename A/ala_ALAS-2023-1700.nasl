#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2023-1700.
##

include('compat.inc');

if (description)
{
  script_id(172181);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id("CVE-2023-22490", "CVE-2023-23946");

  script_name(english:"Amazon Linux AMI : git (ALAS-2023-1700)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of git installed on the remote host is prior to 2.38.4-1.80. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2023-1700 advisory.

  - Git is a revision control system. Using a specially-crafted repository, Git prior to versions 2.39.2,
    2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8 can be tricked into using its
    local clone optimization even when using a non-local transport. Though Git will abort local clones whose
    source `$GIT_DIR/objects` directory contains symbolic links, the `objects` directory itself may still be a
    symbolic link. These two may be combined to include arbitrary files based on known paths on the victim's
    filesystem within the malicious repository's working copy, allowing for data exfiltration in a similar
    manner as CVE-2022-39253. A fix has been prepared and will appear in v2.39.2 v2.38.4 v2.37.6 v2.36.5
    v2.35.7 v2.34.7 v2.33.7 v2.32.6, v2.31.7 and v2.30.8. If upgrading is impractical, two short-term
    workarounds are available. Avoid cloning repositories from untrusted sources with `--recurse-submodules`.
    Instead, consider cloning repositories without recursively cloning their submodules, and instead run `git
    submodule update` at each layer. Before doing so, inspect each new `.gitmodules` file to ensure that it
    does not contain suspicious module URLs. (CVE-2023-22490)

  - Git, a revision control system, is vulnerable to path traversal prior to versions 2.39.2, 2.38.4, 2.37.6,
    2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8. By feeding a crafted input to `git apply`, a
    path outside the working tree can be overwritten as the user who is running `git apply`. A fix has been
    prepared and will appear in v2.39.2, v2.38.4, v2.37.6, v2.36.5, v2.35.7, v2.34.7, v2.33.7, v2.32.6,
    v2.31.7, and v2.30.8. As a workaround, use `git apply --stat` to inspect a patch before applying; avoid
    applying one that creates a symbolic link and then creates a file beyond the symbolic link.
    (CVE-2023-23946)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2023-1700.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-22490.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23946.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update git' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'emacs-git-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'emacs-git-el-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-2.38.4-1.80.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-2.38.4-1.80.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-all-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-bzr-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.38.4-1.80.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-2.38.4-1.80.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-core-doc-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-cvs-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.38.4-1.80.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-daemon-2.38.4-1.80.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debuginfo-2.38.4-1.80.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-debuginfo-2.38.4-1.80.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-email-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-hg-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-instaweb-2.38.4-1.80.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-instaweb-2.38.4-1.80.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-p4-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.38.4-1.80.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-subtree-2.38.4-1.80.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-svn-2.38.4-1.80.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-svn-2.38.4-1.80.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gitweb-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Git-SVN-2.38.4-1.80.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / etc");
}