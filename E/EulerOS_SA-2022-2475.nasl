#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165850);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/09");

  script_cve_id(
    "CVE-2020-11758",
    "CVE-2020-11759",
    "CVE-2020-11760",
    "CVE-2020-11761",
    "CVE-2020-11762",
    "CVE-2020-11763",
    "CVE-2020-11764",
    "CVE-2020-11765",
    "CVE-2020-15305",
    "CVE-2020-15306",
    "CVE-2021-3474",
    "CVE-2021-3475",
    "CVE-2021-3476",
    "CVE-2021-3477",
    "CVE-2021-3478",
    "CVE-2021-3479",
    "CVE-2021-3598",
    "CVE-2021-3605",
    "CVE-2021-3933",
    "CVE-2021-20296",
    "CVE-2021-23215",
    "CVE-2021-26260"
  );

  script_name(english:"EulerOS 2.0 SP8 : OpenEXR (EulerOS-SA-2022-2475)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the OpenEXR package installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read in
    ImfOptimizedPixelReading.h. (CVE-2020-11758)

  - An issue was discovered in OpenEXR before 2.4.1. Because of integer overflows in
    CompositeDeepScanLine::Data::handleDeepFrameBuffer and readSampleCountForLineBlock, an attacker can write
    to an out-of-bounds pointer. (CVE-2020-11759)

  - An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read during RLE uncompression
    in rleUncompress in ImfRle.cpp. (CVE-2020-11760)

  - An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read during Huffman
    uncompression, as demonstrated by FastHufDecoder::refill in ImfFastHuf.cpp. (CVE-2020-11761)

  - An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds read and write in
    DwaCompressor::uncompress in ImfDwaCompressor.cpp when handling the UNKNOWN compression case.
    (CVE-2020-11762)

  - An issue was discovered in OpenEXR before 2.4.1. There is an std::vector out-of-bounds read and write, as
    demonstrated by ImfTileOffsets.cpp. (CVE-2020-11763)

  - An issue was discovered in OpenEXR before 2.4.1. There is an out-of-bounds write in copyIntoFrameBuffer in
    ImfMisc.cpp. (CVE-2020-11764)

  - An issue was discovered in OpenEXR before 2.4.1. There is an off-by-one error in use of the ImfXdr.h read
    function by DwaCompressor::Classifier::Classifier, leading to an out-of-bounds read. (CVE-2020-11765)

  - An issue was discovered in OpenEXR before 2.5.2. Invalid input could cause a use-after-free in
    DeepScanLineInputFile::DeepScanLineInputFile() in IlmImf/ImfDeepScanLineInputFile.cpp. (CVE-2020-15305)

  - An issue was discovered in OpenEXR before v2.5.2. Invalid chunkCount attributes could cause a heap buffer
    overflow in getChunkOffsetTableSize() in IlmImf/ImfMisc.cpp. (CVE-2020-15306)

  - A flaw was found in OpenEXR in versions before 3.0.0-beta. A crafted input file supplied by an attacker,
    that is processed by the Dwa decompression functionality of OpenEXR's IlmImf library, could cause a NULL
    pointer dereference. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20296)

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR.
    (CVE-2021-23215)

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR. This
    is a different flaw from CVE-2021-23215. (CVE-2021-26260)

  - There's a flaw in OpenEXR in versions before 3.0.0-beta. A crafted input file that is processed by OpenEXR
    could cause a shift overflow in the FastHufDecoder, potentially leading to problems with application
    availability. (CVE-2021-3474)

  - There is a flaw in OpenEXR in versions before 3.0.0-beta. An attacker who can submit a crafted file to be
    processed by OpenEXR could cause an integer overflow, potentially leading to problems with application
    availability. (CVE-2021-3475)

  - A flaw was found in OpenEXR's B44 uncompression functionality in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to OpenEXR could trigger shift overflows, potentially affecting
    application availability. (CVE-2021-3476)

  - There's a flaw in OpenEXR's deep tile sample size calculations in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to be processed by OpenEXR could trigger an integer overflow,
    subsequently leading to an out-of-bounds read. The greatest risk of this flaw is to application
    availability. (CVE-2021-3477)

  - There's a flaw in OpenEXR's scanline input file functionality in versions before 3.0.0-beta. An attacker
    able to submit a crafted file to be processed by OpenEXR could consume excessive system memory. The
    greatest impact of this flaw is to system availability. (CVE-2021-3478)

  - There's a flaw in OpenEXR's Scanline API functionality in versions before 3.0.0-beta. An attacker who is
    able to submit a crafted file to be processed by OpenEXR could trigger excessive consumption of memory,
    resulting in an impact to system availability. (CVE-2021-3479)

  - There's a flaw in OpenEXR's ImfDeepScanLineInputFile functionality in versions prior to 3.0.5. An attacker
    who is able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds
    read. The greatest risk from this flaw is to application availability. (CVE-2021-3598)

  - There's a flaw in OpenEXR's rleUncompress functionality in versions prior to 3.0.5. An attacker who is
    able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds read. The
    greatest risk from this flaw is to application availability. (CVE-2021-3605)

  - An integer overflow could occur when OpenEXR processes a crafted file on systems where size_t < 64 bits.
    This could cause an invalid bytesPerLine and maxBytesPerLine value, which could lead to problems with
    application stability or lead to other attack paths. (CVE-2021-3933)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2475
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35e2d207");
  script_set_attribute(attribute:"solution", value:
"Update the affected OpenEXR packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3476");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:OpenEXR-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "OpenEXR-libs-2.2.0-15.h3.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenEXR");
}
