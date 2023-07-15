#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-893.
#

include("compat.inc");

if (description)
{
  script_id(103227);
  script_version("3.5");
  script_cvs_date("Date: 2019/05/13 11:02:56");

  script_cve_id("CVE-2017-1000115", "CVE-2017-1000116");
  script_xref(name:"ALAS", value:"2017-893");

  script_name(english:"Amazon Linux AMI : mercurial (ALAS-2017-893)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A shell command injection flaw related to the handling of 'ssh' URLs
has been discovered in Mercurial. This can be exploited to execute
shell commands with the privileges of the user running the Mercurial
client, for example, when performing a 'checkout' or 'update' action
on a sub-repository within a malicious repository or a legitimate
repository containing a malicious commit. (CVE-2017-1000116)

A vulnerability was found in the way Mercurial handles path auditing
and caches the results. An attacker could abuse a repository with a
series of commits mixing symlinks and regular files/directories to
trick Mercurial into writing outside of a given repository.
(CVE-2017-1000115)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-893.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mercurial' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-mercurial-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-python27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"emacs-mercurial-4.2.3-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-mercurial-el-4.2.3-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-common-4.2.3-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-debuginfo-4.2.3-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-python26-4.2.3-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-python27-4.2.3-1.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-mercurial / emacs-mercurial-el / mercurial-common / etc");
}
