#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1011.
#

include("compat.inc");

if (description)
{
  script_id(109690);
  script_version("1.1");
  script_cvs_date("Date: 2018/05/11 12:23:24");

  script_cve_id("CVE-2017-15041", "CVE-2017-15042", "CVE-2018-6574");
  script_xref(name:"ALAS", value:"2018-1011");

  script_name(english:"Amazon Linux 2 : golang (ALAS-2018-1011)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Arbitrary code execution during go get or go get -d

Go before 1.8.4 and 1.9.x before 1.9.1 allows 'go get' remote command
execution. Using custom domains, it is possible to arrange things so
that example.com/pkg1 points to a Subversion repository but
example.com/pkg1/pkg2 points to a Git repository. If the Subversion
repository includes a Git checkout in its pkg2 directory and some
other work is done to ensure the proper ordering of operations, 'go
get' can be tricked into reusing this Git checkout for the fetch of
code from pkg2. If the Subversion repository's Git checkout has
malicious commands in .git/hooks/, they will execute on the system
running 'go get.'(CVE-2017-15041)

smtp.PlainAuth susceptible to man-in-the-middle password harvesting

An unintended cleartext issue exists in Go before 1.8.4 and 1.9.x
before 1.9.1. RFC 4954 requires that, during SMTP, the PLAIN auth
scheme must only be used on network connections secured with TLS. The
original implementation of smtp.PlainAuth in Go 1.0 enforced this
requirement, and it was documented to do so. In 2013, upstream issue
#5184, this was changed so that the server may decide whether PLAIN is
acceptable. The result is that if you set up a man-in-the-middle SMTP
server that doesn't advertise STARTTLS and does advertise that PLAIN
auth is OK, the smtp.PlainAuth implementation sends the username and
password.(CVE-2017-15042)

Arbitrary code execution during 'go get' via C compiler options

An arbitrary command execution flaw was found in the way Go's 'go get'
command handled gcc and clang sensitive options during the build. A
remote attacker capable of hosting malicious repositories could
potentially use this flaw to cause arbitrary command execution on the
client side.(CVE-2018-6574)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1011.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update golang' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"golang-1.9.4-1.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"golang-bin-1.9.4-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"golang-docs-1.9.4-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"golang-misc-1.9.4-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"golang-src-1.9.4-1.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"golang-tests-1.9.4-1.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / golang-misc / golang-src / etc");
}
