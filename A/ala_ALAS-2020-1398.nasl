#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1398.
#

include("compat.inc");

if (description)
{
  script_id(138640);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2018-21009", "CVE-2019-10871", "CVE-2019-11459", "CVE-2019-12293", "CVE-2019-9959");
  script_xref(name:"ALAS", value:"2020-1398");

  script_name(english:"Amazon Linux AMI : poppler (ALAS-2020-1398)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The tiff_document_render() and tiff_document_get_thumbnail() functions
in the TIFF document backend in GNOME Evince through 3.32.0 did not
handle errors from TIFFReadRGBAImageOriented(), leading to
uninitialized memory use when processing certain TIFF image files.
(CVE-2019-11459)

Poppler before 0.66.0 has an integer overflow in Parser::makeStream in
Parser.cc. (CVE-2018-21009)

The JPXStream::init function in Poppler 0.78.0 and earlier doesn't
check for negative values of stream length, leading to an Integer
Overflow, thereby making it possible to allocate a large memory chunk
on the heap, with a size controlled by an attacker, as demonstrated by
pdftocairo. (CVE-2019-9959)

An issue was discovered in Poppler 0.74.0. There is a heap-based
buffer over-read in the function PSOutputDev::checkPageSlice at
PSOutputDev.cc. (CVE-2019-10871)

In Poppler through 0.76.1, there is a heap-based buffer over-read in
JPXStream::init in JPEG2000Stream.cc via data with inconsistent
heights or widths. (CVE-2019-12293)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1398.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update poppler' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"poppler-0.26.5-42.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-cpp-0.26.5-42.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-cpp-devel-0.26.5-42.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-debuginfo-0.26.5-42.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-devel-0.26.5-42.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-glib-0.26.5-42.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-glib-devel-0.26.5-42.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-utils-0.26.5-42.20.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-cpp / poppler-cpp-devel / poppler-debuginfo / etc");
}
