#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-948.
#

include("compat.inc");

if (description)
{
  script_id(106693);
  script_version("3.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-15298");
  script_xref(name:"ALAS", value:"2018-948");

  script_name(english:"Amazon Linux AMI : git (ALAS-2018-948)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mishandling layers of tree objects

Git through 2.14.2 mishandles layers of tree objects, which allows
remote attackers to cause a denial of service (memory consumption) via
a crafted repository, aka a Git bomb. This can also have an impact of
disk consumption; however, an affected process typically would not
survive its attempt to build the data structure in memory before
writing to disk. (CVE-2017-15298)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-948.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update git' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"emacs-git-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-git-el-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-all-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-bzr-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-cvs-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-daemon-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-debuginfo-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-email-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-hg-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-p4-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-svn-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gitweb-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-2.13.6-2.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-SVN-2.13.6-2.56.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
