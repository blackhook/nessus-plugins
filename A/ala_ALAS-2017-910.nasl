#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-910.
#

include("compat.inc");

if (description)
{
  script_id(103823);
  script_version("3.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_xref(name:"ALAS", value:"2017-910");

  script_name(english:"Amazon Linux AMI : git (ALAS-2017-910)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The 'git' subcommand 'cvsserver' is a Perl script which makes
excessive use of the backtick operator to invoke 'git'. Unfortunately
user input is used within some of those invocations. It should be
noted, that 'git-cvsserver' will be invoked by 'git-shell' by default
without further configuration.

http://seclists.org/oss-sec/2017/q3/534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/CVE-2017-NONE"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-910.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update git' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"emacs-git-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-git-el-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-all-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-bzr-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-cvs-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-daemon-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-debuginfo-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-email-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-hg-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-p4-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-svn-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gitweb-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-2.13.6-1.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-SVN-2.13.6-1.55.amzn1")) flag++;

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
