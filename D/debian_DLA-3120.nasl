#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3120. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165449);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-20650",
    "CVE-2019-9903",
    "CVE-2019-9959",
    "CVE-2019-14494",
    "CVE-2020-27778",
    "CVE-2022-27337",
    "CVE-2022-38784"
  );
  script_xref(name:"IAVB", value:"2022-B-0039-S");
  script_xref(name:"IAVB", value:"2022-B-0050");

  script_name(english:"Debian DLA-3120-1 : poppler - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3120 advisory.

  - An issue was discovered in Poppler 0.71.0. There is a memory leak in GfxColorSpace::setDisplayProfile in
    GfxState.cc, as demonstrated by pdftocairo. (CVE-2018-18897)

  - An issue was discovered in Poppler 0.71.0. There is a reachable abort in Object.h, will lead to denial of
    service because EmbFile::save2 in FileSpec.cc lacks a stream check before saving an embedded file.
    (CVE-2018-19058)

  - A reachable Object::dictLookup assertion in Poppler 0.72.0 allows attackers to cause a denial of service
    due to the lack of a check for the dict data type, as demonstrated by use of the FileSpec class (in
    FileSpec.cc) in pdfdetach. (CVE-2018-20650)

  - An issue was discovered in Poppler through 0.78.0. There is a divide-by-zero error in the function
    SplashOutputDev::tilingPatternFill at SplashOutputDev.cc. (CVE-2019-14494)

  - PDFDoc::markObject in PDFDoc.cc in Poppler 0.74.0 mishandles dict marking, leading to stack consumption in
    the function Dict::find() located at Dict.cc, which can (for example) be triggered by passing a crafted
    pdf file to the pdfunite binary. (CVE-2019-9903)

  - The JPXStream::init function in Poppler 0.78.0 and earlier doesn't check for negative values of stream
    length, leading to an Integer Overflow, thereby making it possible to allocate a large memory chunk on the
    heap, with a size controlled by an attacker, as demonstrated by pdftocairo. (CVE-2019-9959)

  - A flaw was found in Poppler in the way certain PDF files were converted into HTML. A remote attacker could
    exploit this flaw by providing a malicious PDF file that, when processed by the 'pdftohtml' program, would
    crash the application causing a denial of service. (CVE-2020-27778)

  - A logic error in the Hints::Hints function of Poppler v22.03.0 allows attackers to cause a Denial of
    Service (DoS) via a crafted PDF file. (CVE-2022-27337)

  - Poppler prior to and including 22.08.0 contains an integer overflow in the JBIG2 decoder
    (JBIG2Stream::readTextRegionSeg() in JBIGStream.cc). Processing a specially crafted PDF file or JBIG2
    image could lead to a crash or the execution of arbitrary code. This is similar to the vulnerability
    described by CVE-2022-38171 in Xpdf. (CVE-2022-38784)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=913164");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/poppler");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3120");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-19058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-9903");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-9959");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27337");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38784");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/poppler");
  script_set_attribute(attribute:"solution", value:
"Upgrade the poppler packages.

For Debian 10 buster, these problems have been fixed in version 0.71.0-5+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27778");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-38784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp0v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler82");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'gir1.2-poppler-0.18', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-cpp-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-cpp0v5', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-glib-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-glib-doc', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-glib8', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-private-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-qt5-1', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-qt5-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler82', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'poppler-utils', 'reference': '0.71.0-5+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-poppler-0.18 / libpoppler-cpp-dev / libpoppler-cpp0v5 / etc');
}
