#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1371.
#

include("compat.inc");

if (description)
{
  script_id(132259);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387", "CVE-2019-19604");
  script_xref(name:"ALAS", value:"2019-1371");

  script_name(english:"Amazon Linux 2 : git (ALAS-2019-1371)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Git mistakes some paths for relative paths allowing writing outside of
the worktree while cloning (CVE-2019-1351)

NTFS protections inactive when running Git in the Windows Subsystem
for Linux (CVE-2019-1353)

remote code execution in recursive clones with nested submodules
(CVE-2019-1387)

Arbitrary path overwriting via export-marks command option
(CVE-2019-1348)

Files inside the .git directory may be overwritten during cloning via
NTFS Alternate Data Streams (CVE-2019-1352)

recursive submodule cloning allows using git directory twice with
synonymous directory name written in .git/ (CVE-2019-1349)

Incorrect quoting of command-line arguments allowed remote code
execution during a recursive clone (CVE-2019-1350)

Git does not refuse to write out tracked files with backlashes in
filenames (CVE-2019-1354)

Recursive clone followed by a submodule update could execute code
contained within repository without the user explicitly consent
Arbitrary command execution is possible in Git before 2.20.2, 2.21.x
before 2.21.1, 2.22.x before 2.22.2, 2.23.x before 2.23.1, and 2.24.x
before 2.24.1 because a 'git submodule update' operation can run
commands found in the .gitmodules file of a malicious
repository.(CVE-2019-19604)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1371.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update git' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19604");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"git-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-all-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-core-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-core-doc-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-cvs-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-daemon-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-debuginfo-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-email-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-gui-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-instaweb-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-p4-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-subtree-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"git-svn-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"gitk-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"gitweb-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"perl-Git-2.23.1-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"perl-Git-SVN-2.23.1-1.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-all / git-core / git-core-doc / git-cvs / git-daemon / etc");
}
