#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-975.
#

include("compat.inc");

if (description)
{
  script_id(108600);
  script_version("1.4");
  script_cvs_date("Date: 2019/03/04  9:47:28");

  script_cve_id("CVE-2018-6574", "CVE-2018-7187");
  script_xref(name:"ALAS", value:"2018-975");

  script_name(english:"Amazon Linux AMI : golang (ALAS-2018-975)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Arbitrary code execution during 'go get' via C compiler options :

An arbitrary command execution flaw was found in the way Go's 'go get'
command handled gcc and clang sensitive options during the build. A
remote attacker capable of hosting malicious repositories could
potentially use this flaw to cause arbitrary command execution on the
client side. (CVE-2018-6574)

The 'go get' implementation in Go 1.9.4, when the -insecure
command-line option is used, does not validate the import path
(get/vcs.go only checks for '://' anywhere in the string), which
allows remote attackers to execute arbitrary OS commands via a crafted
website. (CVE-2018-7187)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-975.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update golang' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"golang-1.9.4-2.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-bin-1.9.4-2.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-docs-1.9.4-2.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-misc-1.9.4-2.44.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"golang-race-1.9.4-2.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-src-1.9.4-2.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-tests-1.9.4-2.44.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / golang-misc / golang-race / etc");
}
