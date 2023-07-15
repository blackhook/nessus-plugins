#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1072.
#

include("compat.inc");

if (description)
{
  script_id(117344);
  script_version("1.2");
  script_cvs_date("Date: 2018/09/19 10:04:09");

  script_cve_id("CVE-2018-14404");
  script_xref(name:"ALAS", value:"2018-1072");

  script_name(english:"Amazon Linux AMI : libxml2 (ALAS-2018-1072)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference vulnerability exists in the
xpath.c:xmlXPathCompOpEval() function of libxml2 when parsing invalid
XPath expression. Applications processing untrusted XSL format inputs
with the use of libxml2 library may be vulnerable to denial of service
attack due to crash of the application.(CVE-2018-14404)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1072.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libxml2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/07");
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
if (rpm_check(release:"ALA", reference:"libxml2-2.9.1-6.3.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-debuginfo-2.9.1-6.3.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-devel-2.9.1-6.3.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-python26-2.9.1-6.3.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-python27-2.9.1-6.3.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-static-2.9.1-6.3.52.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-debuginfo / libxml2-devel / libxml2-python26 / etc");
}
