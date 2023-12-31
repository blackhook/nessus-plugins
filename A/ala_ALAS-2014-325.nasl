#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-325.
#

include("compat.inc");

if (description)
{
  script_id(73653);
  script_version("1.5");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2014-0107");
  script_xref(name:"ALAS", value:"2014-325");
  script_xref(name:"RHSA", value:"2014:0348");

  script_name(english:"Amazon Linux AMI : xalan-j2 (ALAS-2014-325)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the secure processing feature of Xalan-Java had
insufficient restrictions defined for certain properties and features.
A remote attacker able to provide Extensible Stylesheet Language
Transformations (XSLT) content to be processed by an application using
Xalan-Java could use this flaw to bypass the intended constraints of
the secure processing feature. Depending on the components available
in the classpath, this could lead to arbitrary remote code execution
in the context of the application server running the application that
uses Xalan-Java. (CVE-2014-0107)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-325.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update xalan-j2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xalan-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xalan-j2-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xalan-j2-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xalan-j2-xsltc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"xalan-j2-2.7.0-9.9.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xalan-j2-demo-2.7.0-9.9.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xalan-j2-javadoc-2.7.0-9.9.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xalan-j2-manual-2.7.0-9.9.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xalan-j2-xsltc-2.7.0-9.9.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xalan-j2 / xalan-j2-demo / xalan-j2-javadoc / xalan-j2-manual / etc");
}
