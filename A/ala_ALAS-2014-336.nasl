#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-336.
#

include("compat.inc");

if (description)
{
  script_id(78279);
  script_version("1.4");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2014-1947", "CVE-2014-1958", "CVE-2014-2030");
  script_xref(name:"ALAS", value:"2014-336");

  script_name(english:"Amazon Linux AMI : ImageMagick (ALAS-2014-336)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was found in the way ImageMagick handled PSD
images that use RLE encoding. An attacker could create a malicious PSD
image file that, when opened in ImageMagick, would cause ImageMagick
to crash or, potentially, execute arbitrary code with the privileges
of the user running ImageMagick.

A buffer overflow flaw affecting ImageMagick when creating PSD images
was reported. The vulnerability is similar to CVE-2014-1947 , except
that CVE-2014-2030 's format string is 'L%06ld' instead of
CVE-2014-1947 's 'L%02ld' due to commit r1448."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-336.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ImageMagick' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"ImageMagick-6.7.8.9-10.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-c++-6.7.8.9-10.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-c++-devel-6.7.8.9-10.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-debuginfo-6.7.8.9-10.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-devel-6.7.8.9-10.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-doc-6.7.8.9-10.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-perl-6.7.8.9-10.15.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
