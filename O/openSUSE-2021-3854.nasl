#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3854-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155770);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id(
    "CVE-2017-18267",
    "CVE-2018-13988",
    "CVE-2018-16646",
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-19059",
    "CVE-2018-19060",
    "CVE-2018-19149",
    "CVE-2018-20481",
    "CVE-2018-20551",
    "CVE-2018-20650",
    "CVE-2018-20662",
    "CVE-2019-7310",
    "CVE-2019-9200",
    "CVE-2019-9631",
    "CVE-2019-9903",
    "CVE-2019-9959",
    "CVE-2019-10871",
    "CVE-2019-10872",
    "CVE-2019-14494",
    "CVE-2020-27778"
  );
  script_xref(name:"IAVB", value:"2018-B-0151-S");
  script_xref(name:"IAVB", value:"2019-B-0001-S");
  script_xref(name:"IAVB", value:"2019-B-0011-S");
  script_xref(name:"IAVB", value:"2019-B-0021-S");
  script_xref(name:"IAVB", value:"2019-B-0064-S");

  script_name(english:"openSUSE 15 Security Update : poppler (openSUSE-SU-2021:3854-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3854-1 advisory.

  - The FoFiType1C::cvtGlyph function in fofi/FoFiType1C.cc in Poppler through 0.64.0 allows remote attackers
    to cause a denial of service (infinite recursion) via a crafted PDF file, as demonstrated by pdftops.
    (CVE-2017-18267)

  - Poppler through 0.62 contains an out of bounds read vulnerability due to an incorrect memory access that
    is not mapped in its memory space, as demonstrated by pdfunite. This can result in memory corruption and
    denial of service. This may be exploitable when a victim opens a specially crafted PDF file.
    (CVE-2018-13988)

  - In Poppler 0.68.0, the Parser::getObj() function in Parser.cc may cause infinite recursion via a crafted
    file. A remote attacker can leverage this for a DoS attack. (CVE-2018-16646)

  - An issue was discovered in Poppler 0.71.0. There is a memory leak in GfxColorSpace::setDisplayProfile in
    GfxState.cc, as demonstrated by pdftocairo. (CVE-2018-18897)

  - An issue was discovered in Poppler 0.71.0. There is a reachable abort in Object.h, will lead to denial of
    service because EmbFile::save2 in FileSpec.cc lacks a stream check before saving an embedded file.
    (CVE-2018-19058)

  - An issue was discovered in Poppler 0.71.0. There is a out-of-bounds read in EmbFile::save2 in FileSpec.cc,
    will lead to denial of service, as demonstrated by utils/pdfdetach.cc not validating embedded files before
    save attempts. (CVE-2018-19059)

  - An issue was discovered in Poppler 0.71.0. There is a NULL pointer dereference in goo/GooString.h, will
    lead to denial of service, as demonstrated by utils/pdfdetach.cc not validating a filename of an embedded
    file before constructing a save path. (CVE-2018-19060)

  - Poppler before 0.70.0 has a NULL pointer dereference in _poppler_attachment_new when called from
    poppler_annot_file_attachment_get_attachment. (CVE-2018-19149)

  - XRef::getEntry in XRef.cc in Poppler 0.72.0 mishandles unallocated XRef entries, which allows remote
    attackers to cause a denial of service (NULL pointer dereference) via a crafted PDF document, when
    XRefEntry::setFlag in XRef.h is called from Parser::makeStream in Parser.cc. (CVE-2018-20481)

  - A reachable Object::getString assertion in Poppler 0.72.0 allows attackers to cause a denial of service
    due to construction of invalid rich media annotation assets in the AnnotRichMedia class in Annot.c.
    (CVE-2018-20551)

  - A reachable Object::dictLookup assertion in Poppler 0.72.0 allows attackers to cause a denial of service
    due to the lack of a check for the dict data type, as demonstrated by use of the FileSpec class (in
    FileSpec.cc) in pdfdetach. (CVE-2018-20650)

  - In Poppler 0.72.0, PDFDoc::setup in PDFDoc.cc allows attackers to cause a denial-of-service (application
    crash caused by Object.h SIGABRT, because of a wrong return value from PDFDoc::setup) by crafting a PDF
    file in which an xref data structure is mishandled during extractPDFSubtype processing. (CVE-2018-20662)

  - An issue was discovered in Poppler 0.74.0. There is a heap-based buffer over-read in the function
    PSOutputDev::checkPageSlice at PSOutputDev.cc. (CVE-2019-10871)

  - An issue was discovered in Poppler 0.74.0. There is a heap-based buffer over-read in the function
    Splash::blitTransparent at splash/Splash.cc. (CVE-2019-10872)

  - An issue was discovered in Poppler through 0.78.0. There is a divide-by-zero error in the function
    SplashOutputDev::tilingPatternFill at SplashOutputDev.cc. (CVE-2019-14494)

  - In Poppler 0.73.0, a heap-based buffer over-read (due to an integer signedness error in the XRef::getEntry
    function in XRef.cc) allows remote attackers to cause a denial of service (application crash) or possibly
    have unspecified other impact via a crafted PDF document, as demonstrated by pdftocairo. (CVE-2019-7310)

  - A heap-based buffer underwrite exists in ImageStream::getLine() located at Stream.cc in Poppler 0.74.0
    that can (for example) be triggered by sending a crafted PDF file to the pdfimages binary. It allows an
    attacker to cause Denial of Service (Segmentation fault) or possibly have unspecified other impact.
    (CVE-2019-9200)

  - Poppler 0.74.0 has a heap-based buffer over-read in the CairoRescaleBox.cc downsample_row_box_filter
    function. (CVE-2019-9631)

  - PDFDoc::markObject in PDFDoc.cc in Poppler 0.74.0 mishandles dict marking, leading to stack consumption in
    the function Dict::find() located at Dict.cc, which can (for example) be triggered by passing a crafted
    pdf file to the pdfunite binary. (CVE-2019-9903)

  - The JPXStream::init function in Poppler 0.78.0 and earlier doesn't check for negative values of stream
    length, leading to an Integer Overflow, thereby making it possible to allocate a large memory chunk on the
    heap, with a size controlled by an attacker, as demonstrated by pdftocairo. (CVE-2019-9959)

  - A flaw was found in Poppler in the way certain PDF files were converted into HTML. A remote attacker could
    exploit this flaw by providing a malicious PDF file that, when processed by the 'pdftohtml' program, would
    crash the application causing a denial of service. (CVE-2020-27778)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1092945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1107597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1115626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1120956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1124150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1127329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1130229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179163");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TS7QPSEQIBQO7BALZOE3TN7IO7IMHK3Y/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?357b921f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-18897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27778");
  script_set_attribute(attribute:"solution", value:
"Update the affected libpoppler73 and / or libpoppler73-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9631");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler73");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler73-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libpoppler73-0.62.0-4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpoppler73-32bit-0.62.0-4.6.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpoppler73 / libpoppler73-32bit');
}
