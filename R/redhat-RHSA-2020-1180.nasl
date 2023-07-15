##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1180. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135041);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2017-11166",
    "CVE-2017-12805",
    "CVE-2017-12806",
    "CVE-2017-18251",
    "CVE-2017-18252",
    "CVE-2017-18254",
    "CVE-2017-18271",
    "CVE-2017-18273",
    "CVE-2017-1000476",
    "CVE-2018-8804",
    "CVE-2018-9133",
    "CVE-2018-10177",
    "CVE-2018-10804",
    "CVE-2018-10805",
    "CVE-2018-11656",
    "CVE-2018-12599",
    "CVE-2018-12600",
    "CVE-2018-13153",
    "CVE-2018-14434",
    "CVE-2018-14435",
    "CVE-2018-14436",
    "CVE-2018-14437",
    "CVE-2018-15607",
    "CVE-2018-16328",
    "CVE-2018-16749",
    "CVE-2018-16750",
    "CVE-2018-18544",
    "CVE-2018-20467",
    "CVE-2019-7175",
    "CVE-2019-7397",
    "CVE-2019-7398",
    "CVE-2019-9956",
    "CVE-2019-10131",
    "CVE-2019-10650",
    "CVE-2019-11470",
    "CVE-2019-11472",
    "CVE-2019-11597",
    "CVE-2019-11598",
    "CVE-2019-12974",
    "CVE-2019-12975",
    "CVE-2019-12976",
    "CVE-2019-12978",
    "CVE-2019-12979",
    "CVE-2019-13133",
    "CVE-2019-13134",
    "CVE-2019-13135",
    "CVE-2019-13295",
    "CVE-2019-13297",
    "CVE-2019-13300",
    "CVE-2019-13301",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13454",
    "CVE-2019-14980",
    "CVE-2019-14981",
    "CVE-2019-15139",
    "CVE-2019-15140",
    "CVE-2019-15141",
    "CVE-2019-16708",
    "CVE-2019-16709",
    "CVE-2019-16710",
    "CVE-2019-16711",
    "CVE-2019-16712",
    "CVE-2019-16713",
    "CVE-2019-17540",
    "CVE-2019-17541",
    "CVE-2019-19948",
    "CVE-2019-19949"
  );
  script_bugtraq_id(
    102428,
    103498,
    104591,
    104687,
    105137,
    106268,
    106315,
    106561,
    106847,
    106848,
    107333,
    107546,
    107646,
    108102,
    108117,
    108448,
    108492,
    108913,
    109099,
    109308,
    109362
  );
  script_xref(name:"RHSA", value:"2020:1180");
  script_xref(name:"IAVB", value:"2019-B-0062-S");
  script_xref(name:"IAVB", value:"2019-B-0032-S");
  script_xref(name:"IAVB", value:"2019-B-0013-S");
  script_xref(name:"IAVB", value:"2019-B-0056-S");

  script_name(english:"RHEL 7 : ImageMagick (RHSA-2020:1180)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1180 advisory.

  - ImageMagick: CPU exhaustion vulnerability in function ReadDDSInfo in coders/dds.c (CVE-2017-1000476)

  - ImageMagick: memory leak vulnerability in ReadXWDImage function in coders/xwd.c (CVE-2017-11166)

  - ImageMagick: memory exhaustion in function ReadTIFFImage causing denial of service (CVE-2017-12805)

  - ImageMagick: memory exhaustion in function format8BIM causing denial of service (CVE-2017-12806)

  - ImageMagick: memory leak in ReadPCDImage function in coders/pcd.c (CVE-2017-18251)

  - ImageMagick: assertion failure in MogrifyImageList function in MagickWand/mogrify.c (CVE-2017-18252)

  - ImageMagick: memory leak in WriteGIFImage function in coders/gif.c (CVE-2017-18254)

  - ImageMagick: infinite loop in ReadMIFFImage function in coders/miff.c (CVE-2017-18271)

  - ImageMagick: infinite loop ReadTXTImage  in function in coders/txt.c (CVE-2017-18273)

  - ImageMagick: Infinite loop in coders/png.c:ReadOneMNGImage() allows attackers to cause a denial of service
    via crafted MNG file (CVE-2018-10177)

  - ImageMagick: Memory leak in WriteTIFFImage (CVE-2018-10804)

  - ImageMagick: Memory leak in ReadYCBCRImage (CVE-2018-10805)

  - ImageMagick: memory leak in ReadDCMImage function in coders/dcm.c (CVE-2018-11656)

  - ImageMagick: out of bounds write in ReadBMPImage and WriteBMPImage in coders/bmp.c (CVE-2018-12599)

  - ImageMagick: out of bounds write ReadDIBImage and WriteDIBImage in coders/dib.c (CVE-2018-12600)

  - ImageMagick: memory leak in the XMagickCommand function in MagickCore/animate.c (CVE-2018-13153)

  - ImageMagick: memory leak for a colormap in WriteMPCImage in coders/mpc.c (CVE-2018-14434)

  - ImageMagick: memory leak in DecodeImage in coders/pcd.c (CVE-2018-14435)

  - ImageMagick: memory leak in ReadMIFFImage in coders/miff.c (CVE-2018-14436)

  - ImageMagick: memory leak in parse8BIM in coders/meta.c (CVE-2018-14437)

  - ImageMagick: CPU Exhaustion via crafted input file (CVE-2018-15607)

  - ImageMagick: NULL pointer dereference in CheckEventLogging function in MagickCore/log.c (CVE-2018-16328)

  - ImageMagick: memory leak in ReadOneJNGImage function in coders/png.c (CVE-2018-16640)

  - ImageMagick: out-of-bounds write in InsertRow function in coders/cut.c (CVE-2018-16642)

  - ImageMagick: missing check for fputc function in multiple files (CVE-2018-16643)

  - ImageMagick: improper check for length in ReadDCMImage of coders/dcm.c and ReadPICTImage of coders/pict.c
    (CVE-2018-16644)

  - ImageMagick: Out-of-memory ReadBMPImage of coders/bmp.c and ReadDIBImage of codes/dib.c (CVE-2018-16645)

  - ImageMagick: reachable assertion in ReadOneJNGImage in coders/png.c (CVE-2018-16749)

  - ImageMagick: Memory leak in the formatIPTCfromBuffer function in coders/meta.c (CVE-2018-16750)

  - ImageMagick: memory leak in WritePDBImage in coders/pdb.c (CVE-2018-17966)

  - ImageMagick: memory leak in ReadBGRImage in coders/bgr.c. (CVE-2018-17967)

  - ImageMagick: memory leak in WritePCXImage in coders/pcx.c (CVE-2018-18016)

  - ImageMagick: infinite loop in the ReadBMPImage function of the coders/bmp.c (CVE-2018-18024)

  - ImageMagick: memory leak in WriteMSLImage of coders/msl.c (CVE-2018-18544)

  - ImageMagick: infinite loop in coders/bmp.c (CVE-2018-20467)

  - ImageMagick: double free in WriteEPTImage function in coders/ept.c (CVE-2018-8804)

  - ImageMagick: excessive iteration in the DecodeLabImage and EncodeLabImage functions in coders/tiff.c
    (CVE-2018-9133)

  - ImageMagick: off-by-one read in formatIPTCfromBuffer function in coders/meta.c (CVE-2019-10131)

  - ImageMagick: heap-based buffer over-read in WriteTIFFImage of coders/tiff.c leads to denial of service or
    information disclosure via crafted image file (CVE-2019-10650)

  - ImageMagick: denial of service in cineon parsing component (CVE-2019-11470)

  - ImageMagick: denial of service in ReadXWDImage in coders/xwd.c in the XWD image parsing component
    (CVE-2019-11472)

  - ImageMagick: heap-based buffer over-read in the function WriteTIFFImage of coders/tiff.c leading to DoS or
    information disclosure (CVE-2019-11597)

  - ImageMagick: heap-based buffer over-read in the function WritePNMImage of coders/pnm.c leading to DoS or
    information disclosure (CVE-2019-11598)

  - imagemagick: null-pointer dereference in function ReadPANGOImage in coders/pango.c and ReadVIDImage in
    coders/vid.c causing denial of service (CVE-2019-12974)

  - imagemagick: memory leak vulnerability in function WriteDPXImage in coders/dpx.c (CVE-2019-12975)

  - imagemagick: memory leak vulnerability in function ReadPCLImage in coders/pcl.c (CVE-2019-12976)

  - imagemagick: use of uninitialized value in function ReadPANGOImage in coders/pango.c (CVE-2019-12978)

  - imagemagick: use of uninitialized value in functionSyncImageSettings in MagickCore/image.c
    (CVE-2019-12979)

  - ImageMagick: a memory leak vulnerability in the function ReadBMPImage in coders/bmp.c (CVE-2019-13133)

  - ImageMagick: a memory leak vulnerability in the function ReadVIFFImage in coders/viff.c (CVE-2019-13134)

  - ImageMagick: a use of uninitialized value vulnerability in the function ReadCUTImage leading to a crash
    and DoS (CVE-2019-13135)

  - ImageMagick: heap-based buffer over-read at MagickCore/threshold.c in AdaptiveThresholdImage because a
    width of zero is mishandled (CVE-2019-13295)

  - ImageMagick: heap-based buffer over-read at MagickCore/threshold.c in AdaptiveThresholdImage because a
    height of zero is mishandled (CVE-2019-13297)

  - ImageMagick: heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages because of mishandling
    columns (CVE-2019-13300)

  - ImageMagick: memory leaks in AcquireMagickMemory (CVE-2019-13301)

  - ImageMagick: stack-based buffer overflow at coders/pnm.c in WritePNMImage because of a misplaced
    assignment (CVE-2019-13304)

  - ImageMagick: stack-based buffer overflow at coders/pnm.c in WritePNMImage because of a misplaced strncpy
    and an off-by-one error (CVE-2019-13305)

  - ImageMagick: stack-based buffer overflow at coders/pnm.c in WritePNMImage because of off-by-one errors
    (CVE-2019-13306)

  - ImageMagick: heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages because of mishandling
    rows (CVE-2019-13307)

  - ImageMagick: memory leaks at AcquireMagickMemory due to mishandling the NoSuchImage error in
    CLIListOperatorImages (CVE-2019-13309)

  - ImageMagick: memory leaks at AcquireMagickMemory because of an error in MagickWand/mogrify.c
    (CVE-2019-13310)

  - ImageMagick: memory leaks at AcquireMagickMemory because of a wand/mogrify.c error (CVE-2019-13311)

  - ImageMagick: division by zero in RemoveDuplicateLayers in MagickCore/layer.c (CVE-2019-13454)

  - ImageMagick: use-after-free in magick/blob.c resulting in a denial of service (CVE-2019-14980)

  - ImageMagick: division by zero in MeanShiftImage in MagickCore/feature.c (CVE-2019-14981)

  - ImageMagick: out-of-bounds read in ReadXWDImage in coders/xwd.c (CVE-2019-15139)

  - ImageMagick: Use after free in ReadMATImage in coders/mat.c (CVE-2019-15140)

  - ImageMagick: heap-based buffer overflow in WriteTIFFImage in coders/tiff.c (CVE-2019-15141)

  - ImageMagick: memory leak in magick/xwindow.c (CVE-2019-16708)

  - ImageMagick: memory leak in coders/dps.c (CVE-2019-16709)

  - ImageMagick: memory leak in coders/dot.c (CVE-2019-16710, CVE-2019-16713)

  - ImageMagick: memory leak in Huffman2DEncodeImage in coders/ps2.c (CVE-2019-16711)

  - ImageMagick: memory leak in Huffman2DEncodeImage in coders/ps3.c (CVE-2019-16712)

  - ImageMagick: heap-based buffer overflow in ReadPSInfo in coders/ps.c (CVE-2019-17540)

  - ImageMagick: Use after free in ReadICCProfile function in coders/jpeg.c (CVE-2019-17541)

  - ImageMagick: heap-based buffer overflow in WriteSGIImage in coders/sgi.c (CVE-2019-19948)

  - ImageMagick: heap-based buffer over-read in WritePNGImage in coders/png.c (CVE-2019-19949)

  - imagemagick: memory leak in function DecodeImage in coders/pcd.c (CVE-2019-7175)

  - ImageMagick: Memory leak in the WritePDFImage function in coders/pdf.c (CVE-2019-7397)

  - ImageMagick: Memory leak in the WriteDIBImage function in coders/dib.c (CVE-2019-7398)

  - imagemagick: stack-based buffer overflow in function PopHexPixel in coders/ps.c (CVE-2019-9956)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-11166");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-12805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-12806");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18251");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18252");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18254");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18271");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-18273");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-1000476");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-8804");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-9133");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-10177");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-10804");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-10805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-11656");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-12599");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-12600");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-13153");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14434");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14435");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14436");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-14437");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-15607");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16328");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16642");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16644");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16645");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16749");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16750");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17966");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17967");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-18016");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-18024");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-18544");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-20467");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7175");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7397");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-7398");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-9956");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10131");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10650");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11470");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11472");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11597");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11598");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12975");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12976");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12978");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12979");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13133");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13134");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13135");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13295");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13297");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13300");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13301");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13304");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13305");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13306");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13307");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13309");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13310");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13311");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-13454");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14980");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14981");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15139");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15140");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15141");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16708");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16709");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16710");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16711");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16712");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16713");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17540");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-17541");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19948");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19949");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1532845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1559892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1561741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1561742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1561744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1563875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1572044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1577398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1577399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1581486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1581489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1588170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1594338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1594339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1598471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1609933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1609936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1609939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1609942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1622738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1624955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1626570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1626591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1626599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1626606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1626611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1627916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1627917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1636579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1636587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1636590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1637189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1642614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1664845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1672560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1672564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1687436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1692300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1700755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1704762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1705406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1705414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1707768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1707770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1708517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1708521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1726078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1726081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1726104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1728474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1730604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1732278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1732282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1732284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1732292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1732294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1757779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1757911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1765330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1767087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1767802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1767812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1767828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1772643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1792480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1793177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1801681");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19948");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 121, 122, 125, 193, 200, 248, 369, 400, 401, 416, 456, 476, 617, 772, 787, 835);

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autotrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autotrace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:emacs-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:inkscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:inkscape-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:inkscape-view");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/os',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/os',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/os',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'autotrace-0.31.1-38.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'autotrace-devel-0.31.1-38.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'emacs-24.3-23.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-24.3-23.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-24.3-23.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-24.3-23.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-common-24.3-23.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-common-24.3-23.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-common-24.3-23.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-common-24.3-23.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-el-24.3-23.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-filesystem-24.3-23.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-nox-24.3-23.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-nox-24.3-23.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-nox-24.3-23.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-nox-24.3-23.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'emacs-terminal-24.3-23.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ImageMagick-6.9.10.68-3.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-c++-6.9.10.68-3.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-c++-devel-6.9.10.68-3.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-devel-6.9.10.68-3.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-doc-6.9.10.68-3.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-doc-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-doc-6.9.10.68-3.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-doc-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-perl-6.9.10.68-3.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-perl-6.9.10.68-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-perl-6.9.10.68-3.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ImageMagick-perl-6.9.10.68-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-0.92.2-3.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-0.92.2-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-0.92.2-3.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-0.92.2-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-docs-0.92.2-3.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-docs-0.92.2-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-docs-0.92.2-3.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-docs-0.92.2-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-view-0.92.2-3.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-view-0.92.2-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-view-0.92.2-3.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'inkscape-view-0.92.2-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc');
}
