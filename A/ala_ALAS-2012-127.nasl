#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-127.
#

include("compat.inc");

if (description)
{
  script_id(69617);
  script_version("1.6");
  script_cvs_date("Date: 2018/04/18 15:09:34");

  script_cve_id("CVE-2012-4405");
  script_xref(name:"ALAS", value:"2012-127");
  script_xref(name:"RHSA", value:"2012:1256");

  script_name(english:"Amazon Linux AMI : ghostscript (ALAS-2012-127)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow flaw, leading to a heap-based buffer overflow, was
found in Ghostscript's International Color Consortium Format library
(icclib). An attacker could create a specially crafted PostScript or
PDF file with embedded images that would cause Ghostscript to crash
or, potentially, execute arbitrary code with the privileges of the
user running Ghostscript. (CVE-2012-4405)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-127.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ghostscript' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ghostscript-8.70-15.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-debuginfo-8.70-15.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-devel-8.70-15.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-doc-8.70-15.22.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-debuginfo / ghostscript-devel / etc");
}
