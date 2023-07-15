#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1325.
#

include("compat.inc");

if (description)
{
  script_id(132026);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387");
  script_xref(name:"ALAS", value:"2019-1325");

  script_name(english:"Amazon Linux AMI : git (ALAS-2019-1325)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The --export-marks option of git fast-import is exposed also via the
in-stream command feature export-marks=... and it allows overwriting
arbitrary paths.(CVE-2019-1348)

When submodules are cloned recursively, under certain circumstances
Git could be fooled into using the same Git directory twice. We now
require the directory to be empty.(CVE-2019-1349)

Incorrect quoting of command-line arguments allowed remote code
execution during a recursive clone in conjunction with SSH URLs.
(CVE-2019-1350)

While the only permitted drive letters for physical drives on Windows
are letters of the US-English alphabet, this restriction does not
apply to virtual drives . Git mistook such paths for relative paths,
allowing writing outside of the worktree while cloning.
(CVE-2019-13510)

Git was unaware of NTFS Alternate Data Streams, allowing files inside
the .git/ directory to be overwritten during a clone.(CVE-2019-1352)

When running Git in the Windows Subsystem for Linux (also known as
'WSL') while accessing a working directory on a regular Windows drive,
none of the NTFS protections were active. (CVE-2019-1353)

Filenames on Linux/Unix can contain backslashes. On Windows,
backslashes are directory separators. Git did not use to refuse to
write out tracked files with such filenames.(CVE-2019-1354)

Recursive clones are currently affected by a vulnerability that is
caused by too-lax validation of submodule names, allowing very
targeted attacks via remote code execution in recursive
clones.(CVE-2019-1387)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1325.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update git' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1354");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"emacs-git-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-git-el-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-all-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-bzr-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-cvs-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-daemon-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-debuginfo-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-email-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-hg-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-p4-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-svn-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gitweb-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-2.14.6-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-SVN-2.14.6-1.61.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
