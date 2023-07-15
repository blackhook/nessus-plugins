#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-141.
#

include("compat.inc");

if (description)
{
  script_id(69631);
  script_version("1.7");
  script_cvs_date("Date: 2019/04/18  9:41:10");

  script_cve_id("CVE-2012-1688");
  script_xref(name:"ALAS", value:"2012-141");
  script_xref(name:"RHSA", value:"2012:1462");

  script_name(english:"Amazon Linux AMI : mysql51 (ALAS-2012-141)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory pages, listed below.

- http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixMSQL
  (April 2012)

- http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html#AppendixMSQL
  (July 2012)

- http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html#AppendixMSQL
  (October 2012)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-141.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql51' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"mysql51-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-bench-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-common-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-debuginfo-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-devel-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-embedded-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-embedded-devel-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-libs-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-server-5.1.66-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-test-5.1.66-1.56.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql51 / mysql51-bench / mysql51-common / mysql51-debuginfo / etc");
}
