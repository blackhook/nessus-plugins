#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153304);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/16");

  script_cve_id(
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-19059",
    "CVE-2018-19060",
    "CVE-2018-20650",
    "CVE-2018-20662",
    "CVE-2019-10871",
    "CVE-2019-9903"
  );

  script_name(english:"EulerOS 2.0 SP2 : poppler (EulerOS-SA-2021-2425)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the poppler packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - PDFDoc::markObject in PDFDoc.cc in Poppler 0.74.0
    mishandles dict marking, leading to stack consumption
    in the function Dict::find() located at Dict.cc, which
    can (for example) be triggered by passing a crafted pdf
    file to the pdfunite binary.(CVE-2019-9903)

  - An issue was discovered in Poppler 0.71.0. There is a
    memory leak in GfxColorSpace::setDisplayProfile in
    GfxState.cc, as demonstrated by
    pdftocairo.(CVE-2018-18897)

  - An issue was discovered in Poppler 0.71.0. There is a
    reachable abort in Object.h, will lead to denial of
    service because EmbFile::save2 in FileSpec.cc lacks a
    stream check before saving an embedded
    file.(CVE-2018-19058)

  - An issue was discovered in Poppler 0.71.0. There is a
    NULL pointer dereference in goo/GooString.h, will lead
    to denial of service, as demonstrated by
    utils/pdfdetach.cc not validating a filename of an
    embedded file before constructing a save
    path.(CVE-2018-19060)

  - An issue was discovered in Poppler 0.71.0. There is a
    out-of-bounds read in EmbFile::save2 in FileSpec.cc,
    will lead to denial of service, as demonstrated by
    utils/pdfdetach.cc not validating embedded files before
    save attempts.(CVE-2018-19059)

  - A reachable Object::dictLookup assertion in Poppler
    0.72.0 allows attackers to cause a denial of service
    due to the lack of a check for the dict data type, as
    demonstrated by use of the FileSpec class (in
    FileSpec.cc) in pdfdetach.(CVE-2018-20650)

  - An issue was discovered in Poppler 0.74.0. There is a
    heap-based buffer over-read in the function
    PSOutputDev::checkPageSlice at
    PSOutputDev.cc.(CVE-2019-10871)

  - In Poppler 0.72.0, PDFDoc::setup in PDFDoc.cc allows
    attackers to cause a denial-of-service (application
    crash caused by Object.h SIGABRT, because of a wrong
    return value from PDFDoc::setup) by crafting a PDF file
    in which an xref data structure is mishandled during
    extractPDFSubtype processing.(CVE-2018-20662)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2425
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3e43183");
  script_set_attribute(attribute:"solution", value:
"Update the affected poppler packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9903");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["poppler-0.26.5-17.h24",
        "poppler-glib-0.26.5-17.h24",
        "poppler-qt-0.26.5-17.h24",
        "poppler-utils-0.26.5-17.h24"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
