#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0249. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132446);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-16646",
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-19059",
    "CVE-2018-19060",
    "CVE-2018-19149",
    "CVE-2018-20481",
    "CVE-2018-20650",
    "CVE-2018-20662",
    "CVE-2019-7310",
    "CVE-2019-9200",
    "CVE-2019-9631"
  );
  script_bugtraq_id(
    106031,
    106321,
    106459,
    106659,
    106829,
    107172
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : poppler Multiple Vulnerabilities (NS-SA-2019-0249)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has poppler packages installed that are affected
by multiple vulnerabilities:

  - Poppler before 0.70.0 has a NULL pointer dereference in
    _poppler_attachment_new when called from
    poppler_annot_file_attachment_get_attachment.
    (CVE-2018-19149)

  - In Poppler 0.68.0, the Parser::getObj() function in
    Parser.cc may cause infinite recursion via a crafted
    file. A remote attacker can leverage this for a DoS
    attack. (CVE-2018-16646)

  - An issue was discovered in Poppler 0.71.0. There is a
    memory leak in GfxColorSpace::setDisplayProfile in
    GfxState.cc, as demonstrated by pdftocairo.
    (CVE-2018-18897)

  - An issue was discovered in Poppler 0.71.0. There is a
    reachable abort in Object.h, will lead to denial of
    service because EmbFile::save2 in FileSpec.cc lacks a
    stream check before saving an embedded file.
    (CVE-2018-19058)

  - An issue was discovered in Poppler 0.71.0. There is a
    out-of-bounds read in EmbFile::save2 in FileSpec.cc,
    will lead to denial of service, as demonstrated by
    utils/pdfdetach.cc not validating embedded files before
    save attempts. (CVE-2018-19059)

  - An issue was discovered in Poppler 0.71.0. There is a
    NULL pointer dereference in goo/GooString.h, will lead
    to denial of service, as demonstrated by
    utils/pdfdetach.cc not validating a filename of an
    embedded file before constructing a save path.
    (CVE-2018-19060)

  - In Poppler 0.73.0, a heap-based buffer over-read (due to
    an integer signedness error in the XRef::getEntry
    function in XRef.cc) allows remote attackers to cause a
    denial of service (application crash) or possibly have
    unspecified other impact via a crafted PDF document, as
    demonstrated by pdftocairo. (CVE-2019-7310)

  - A heap-based buffer underwrite exists in
    ImageStream::getLine() located at Stream.cc in Poppler
    0.74.0 that can (for example) be triggered by sending a
    crafted PDF file to the pdfimages binary. It allows an
    attacker to cause Denial of Service (Segmentation fault)
    or possibly have unspecified other impact.
    (CVE-2019-9200)

  - Poppler 0.74.0 has a heap-based buffer over-read in the
    CairoRescaleBox.cc downsample_row_box_filter function.
    (CVE-2019-9631)

  - In Poppler 0.72.0, PDFDoc::setup in PDFDoc.cc allows
    attackers to cause a denial-of-service (application
    crash caused by Object.h SIGABRT, because of a wrong
    return value from PDFDoc::setup) by crafting a PDF file
    in which an xref data structure is mishandled during
    extractPDFSubtype processing. (CVE-2018-20662)

  - A reachable Object::dictLookup assertion in Poppler
    0.72.0 allows attackers to cause a denial of service due
    to the lack of a check for the dict data type, as
    demonstrated by use of the FileSpec class (in
    FileSpec.cc) in pdfdetach. (CVE-2018-20650)

  - XRef::getEntry in XRef.cc in Poppler 0.72.0 mishandles
    unallocated XRef entries, which allows remote attackers
    to cause a denial of service (NULL pointer dereference)
    via a crafted PDF document, when XRefEntry::setFlag in
    XRef.h is called from Parser::makeStream in Parser.cc.
    (CVE-2018-20481)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0249");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL poppler packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "poppler-0.26.5-38.el7",
    "poppler-cpp-0.26.5-38.el7",
    "poppler-cpp-devel-0.26.5-38.el7",
    "poppler-debuginfo-0.26.5-38.el7",
    "poppler-demos-0.26.5-38.el7",
    "poppler-devel-0.26.5-38.el7",
    "poppler-glib-0.26.5-38.el7",
    "poppler-glib-devel-0.26.5-38.el7",
    "poppler-qt-0.26.5-38.el7",
    "poppler-qt-devel-0.26.5-38.el7",
    "poppler-utils-0.26.5-38.el7"
  ],
  "CGSL MAIN 5.05": [
    "poppler-0.26.5-38.el7",
    "poppler-cpp-0.26.5-38.el7",
    "poppler-cpp-devel-0.26.5-38.el7",
    "poppler-debuginfo-0.26.5-38.el7",
    "poppler-demos-0.26.5-38.el7",
    "poppler-devel-0.26.5-38.el7",
    "poppler-glib-0.26.5-38.el7",
    "poppler-glib-devel-0.26.5-38.el7",
    "poppler-qt-0.26.5-38.el7",
    "poppler-qt-devel-0.26.5-38.el7",
    "poppler-utils-0.26.5-38.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
