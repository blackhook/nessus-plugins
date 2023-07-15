#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-819.
#

include("compat.inc");

if (description)
{
  script_id(99532);
  script_version("3.4");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-8714");
  script_xref(name:"ALAS", value:"2017-819");

  script_name(english:"Amazon Linux AMI : R (ALAS-2017-819)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An exploitable buffer overflow vulnerability exists in the
LoadEncoding functionality of the R programming language version
3.3.0. A specially crafted R script can cause a buffer overflow
resulting in a memory corruption. An attacker can send a malicious R
script to trigger this vulnerability. (CVE-2017-8714)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-819.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update R' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:R");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:R-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:R-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:R-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:R-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:R-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:R-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libRmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libRmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libRmath-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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
if (rpm_check(release:"ALA", reference:"R-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"R-core-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"R-core-devel-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"R-debuginfo-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"R-devel-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"R-java-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"R-java-devel-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libRmath-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libRmath-devel-3.3.3-1.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libRmath-static-3.3.3-1.51.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "R / R-core / R-core-devel / R-debuginfo / R-devel / R-java / etc");
}
