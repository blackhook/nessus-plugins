#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1047.
#

include("compat.inc");

if (description)
{
  script_id(111338);
  script_version("1.1");
  script_cvs_date("Date: 2018/07/26 13:32:42");

  script_cve_id("CVE-2018-10886");
  script_xref(name:"ALAS", value:"2018-1047");

  script_name(english:"Amazon Linux AMI : ant (ALAS-2018-1047)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Ant's unzip and untar targets permit the
extraction of files outside the target directory. A crafted zip or tar
file submitted to an Ant build could create or overwrite arbitrary
files with the privileges of the user running Ant.(CVE-2018-10886)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1047.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ant' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-xalan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-jdepend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-jmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-jsch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-junit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-swing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-testutil");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/26");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"ant-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-antlr-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-apache-bcel-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-apache-bsf-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-apache-log4j-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-apache-oro-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-apache-regexp-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-apache-resolver-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-apache-xalan2-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-commons-logging-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-commons-net-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-javadoc-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-javamail-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-jdepend-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-jmf-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-jsch-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-junit-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-manual-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-scripts-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-swing-1.8.3-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ant-testutil-1.8.3-1.14.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ant / ant-antlr / ant-apache-bcel / ant-apache-bsf / etc");
}
