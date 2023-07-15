#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1271.
#

include("compat.inc");

if (description)
{
  script_id(128294);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-16646", "CVE-2018-18897", "CVE-2018-19058", "CVE-2018-19059", "CVE-2018-19060", "CVE-2018-19149", "CVE-2018-20481", "CVE-2018-20650", "CVE-2018-20662", "CVE-2019-7310", "CVE-2019-9200", "CVE-2019-9631");
  script_xref(name:"ALAS", value:"2019-1271");

  script_name(english:"Amazon Linux AMI : poppler (ALAS-2019-1271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XRef::getEntry in XRef.cc in Poppler 0.72.0 mishandles unallocated
XRef entries, which allows remote attackers to cause a denial of
service (NULL pointer dereference) via a crafted PDF document, when
XRefEntry::setFlag in XRef.h is called from Parser::makeStream in
Parser.cc.(CVE-2018-20481)

In Poppler 0.68.0, the Parser::getObj() function in Parser.cc may
cause infinite recursion via a crafted file. A remote attacker can
leverage this for a DoS attack. (CVE-2018-16646)

Poppler 0.74.0 has a heap-based buffer over-read in the
CairoRescaleBox.cc downsample_row_box_filter function.(CVE-2019-9631)

A reachable Object::dictLookup assertion in Poppler 0.72.0 allows
attackers to cause a denial of service due to the lack of a check for
the dict data type, as demonstrated by use of the FileSpec class (in
FileSpec.cc) in pdfdetach.(CVE-2018-20650)

An issue was discovered in Poppler 0.71.0. There is a out-of-bounds
read in EmbFile::save2 in FileSpec.cc, will lead to denial of service,
as demonstrated by utils/pdfdetach.cc not validating embedded files
before save attempts.(CVE-2018-19059)

An issue was discovered in Poppler 0.71.0. There is a reachable abort
in Object.h, will lead to denial of service because EmbFile::save2 in
FileSpec.cc lacks a stream check before saving an embedded
file.(CVE-2018-19058)

Poppler before 0.70.0 has a NULL pointer dereference in
_poppler_attachment_new when called from
poppler_annot_file_attachment_get_attachment.(CVE-2018-19149)

In Poppler 0.73.0, a heap-based buffer over-read (due to an integer
signedness error in the XRef::getEntry function in XRef.cc) allows
remote attackers to cause a denial of service (application crash) or
possibly have unspecified other impact via a crafted PDF document, as
demonstrated by pdftocairo.(CVE-2019-7310)

An issue was discovered in Poppler 0.71.0. There is a memory leak in
GfxColorSpace::setDisplayProfile in GfxState.cc, as demonstrated by
pdftocairo.(CVE-2018-18897)

An issue was discovered in Poppler 0.71.0. There is a NULL pointer
dereference in goo/GooString.h, will lead to denial of service, as
demonstrated by utils/pdfdetach.cc not validating a filename of an
embedded file before constructing a save path.(CVE-2018-19060)

A heap-based buffer underwrite exists in ImageStream::getLine()
located at Stream.cc in Poppler 0.74.0 that can (for example) be
triggered by sending a crafted PDF file to the pdfimages binary. It
allows an attacker to cause Denial of Service (Segmentation fault) or
possibly have unspecified other impact.(CVE-2019-9200)

In Poppler 0.72.0, PDFDoc::setup in PDFDoc.cc allows attackers to
cause a denial-of-service (application crash caused by Object.h
SIGABRT, because of a wrong return value from PDFDoc::setup) by
crafting a PDF file in which an xref data structure is mishandled
during extractPDFSubtype processing.(CVE-2018-20662)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1271.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update poppler' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"poppler-0.26.5-38.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-cpp-0.26.5-38.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-cpp-devel-0.26.5-38.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-debuginfo-0.26.5-38.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-devel-0.26.5-38.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-glib-0.26.5-38.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-glib-devel-0.26.5-38.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"poppler-utils-0.26.5-38.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-cpp / poppler-cpp-devel / poppler-debuginfo / etc");
}
