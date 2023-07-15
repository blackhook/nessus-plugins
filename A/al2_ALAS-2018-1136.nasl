#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1136.
#

include("compat.inc");

if (description)
{
  script_id(119790);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id("CVE-2018-19486");
  script_xref(name:"ALAS", value:"2018-1136");

  script_name(english:"Amazon Linux 2 : git (ALAS-2018-1136)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Git before 2.19.2 on Linux and UNIX executes commands from the current
working directory (as if '.' were at the end of $PATH) in certain
cases involving the run_command() API and run-command.c, because there
was a dangerous change from execvp to execv during
2017.(CVE-2018-19486)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1136.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update git' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-subtree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"git-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-all-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-core-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-core-doc-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-cvs-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-daemon-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-debuginfo-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-email-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-gui-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-p4-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-subtree-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"git-svn-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"gitk-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"gitweb-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"perl-Git-2.17.2-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"perl-Git-SVN-2.17.2-2.amzn2")) flag++;

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
