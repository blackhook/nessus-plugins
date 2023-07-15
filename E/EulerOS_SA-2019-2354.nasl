#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131846);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2014-8354",
    "CVE-2014-8355",
    "CVE-2014-8562",
    "CVE-2014-8716",
    "CVE-2014-9821",
    "CVE-2014-9822",
    "CVE-2014-9823",
    "CVE-2014-9824",
    "CVE-2014-9825",
    "CVE-2014-9837",
    "CVE-2014-9852",
    "CVE-2014-9853",
    "CVE-2014-9854",
    "CVE-2014-9907",
    "CVE-2015-8900",
    "CVE-2015-8901",
    "CVE-2015-8902",
    "CVE-2015-8903",
    "CVE-2015-8957",
    "CVE-2015-8958",
    "CVE-2016-10046",
    "CVE-2016-10047",
    "CVE-2016-10049",
    "CVE-2016-10052",
    "CVE-2016-10053",
    "CVE-2016-10054",
    "CVE-2016-10055",
    "CVE-2016-10056",
    "CVE-2016-10057",
    "CVE-2016-10058",
    "CVE-2016-10059",
    "CVE-2016-10060",
    "CVE-2016-10061",
    "CVE-2016-10062",
    "CVE-2016-10063",
    "CVE-2016-10064",
    "CVE-2016-10065",
    "CVE-2016-10066",
    "CVE-2016-10067",
    "CVE-2016-10068",
    "CVE-2016-10069",
    "CVE-2016-10070",
    "CVE-2016-10071",
    "CVE-2016-10144",
    "CVE-2016-10145",
    "CVE-2016-10252",
    "CVE-2016-4562",
    "CVE-2016-4563",
    "CVE-2016-4564",
    "CVE-2016-5687",
    "CVE-2016-5688",
    "CVE-2016-5689",
    "CVE-2016-5690",
    "CVE-2016-5691",
    "CVE-2016-6491",
    "CVE-2016-6823",
    "CVE-2016-7101",
    "CVE-2016-7515",
    "CVE-2016-7516",
    "CVE-2016-7517",
    "CVE-2016-7518",
    "CVE-2016-7519",
    "CVE-2016-7520",
    "CVE-2016-7525",
    "CVE-2016-7526",
    "CVE-2016-7528",
    "CVE-2016-7529",
    "CVE-2016-7530",
    "CVE-2016-7531",
    "CVE-2016-7533",
    "CVE-2016-7534",
    "CVE-2016-7539",
    "CVE-2016-7799",
    "CVE-2016-7906",
    "CVE-2016-8677",
    "CVE-2016-8707",
    "CVE-2016-8866",
    "CVE-2016-9559",
    "CVE-2017-11478",
    "CVE-2017-11505",
    "CVE-2017-11523",
    "CVE-2017-11524",
    "CVE-2017-11525",
    "CVE-2017-11526",
    "CVE-2017-11527",
    "CVE-2017-11528",
    "CVE-2017-11529",
    "CVE-2017-11530",
    "CVE-2017-12427",
    "CVE-2017-13139",
    "CVE-2017-13140",
    "CVE-2017-13141",
    "CVE-2017-13142",
    "CVE-2017-13143",
    "CVE-2017-13144",
    "CVE-2017-13145",
    "CVE-2017-13146",
    "CVE-2017-13658",
    "CVE-2017-17499",
    "CVE-2017-17504",
    "CVE-2017-5507",
    "CVE-2017-5508",
    "CVE-2017-5509",
    "CVE-2017-5510",
    "CVE-2017-6497",
    "CVE-2017-6498",
    "CVE-2017-6499",
    "CVE-2017-6500",
    "CVE-2017-6501",
    "CVE-2017-6502",
    "CVE-2017-7941",
    "CVE-2017-7942",
    "CVE-2017-7943",
    "CVE-2018-16323",
    "CVE-2018-16328",
    "CVE-2018-20467",
    "CVE-2018-6405",
    "CVE-2019-7175"
  );
  script_bugtraq_id(
    70830,
    70837,
    70839,
    70992
  );

  script_name(english:"EulerOS 2.0 SP2 : ImageMagick (EulerOS-SA-2019-2354)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - ImageMagick is an image display and manipulation tool
    for the X Window System. ImageMagick can read and write
    JPEG, TIFF, PNM, GIF,and Photo CD image formats. It can
    resize, rotate, sharpen, color reduce, or add special
    effects to an image, and when finished you can either
    save the completed work in the original format or a
    different one. ImageMagick also includes command line
    programs for creating animated or transparent .gifs,
    creating composite images, creating thumbnail images,
    and more.ImageMagick is one of your choices if you need
    a program to manipulate and display images. If you want
    to develop your own applications which use ImageMagick
    code or APIs, you need to install ImageMagick-devel as
    well.Security Fix(es):In ImageMagick before 7.0.8-25,
    some memory leaks exist in DecodeImage in
    coders/pcd.c.(CVE-2019-7175)ReadXBMImage in
    coders/xbm.c in ImageMagick before 7.0.8-9 leaves data
    uninitialized when processing an XBM file that has a
    negative pixel value. If the affected code is used as a
    library loaded into a process that includes sensitive
    information, that information sometimes can be leaked
    via the image data.(CVE-2018-16323)In ImageMagick
    before 7.0.8-8, a NULL pointer dereference exists in
    the CheckEventLogging function in
    MagickCore/log.c.(CVE-2018-16328)The DrawDashPolygon
    function in MagickCore/draw.c in ImageMagick before
    6.9.4-0 and 7.x before 7.0.1-2 mishandles calculations
    of certain vertices integer data, which allows remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted file.(CVE-2016-4562)The
    TraceStrokePolygon function in MagickCore/draw.c in
    ImageMagick before 6.9.4-0 and 7.x before 7.0.1-2
    mishandles the relationship between the BezierQuantum
    value and certain strokes data, which allows remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted file.(CVE-2016-4563)The
    DrawImage function in MagickCore/draw.c in ImageMagick
    before 6.9.4-0 and 7.x before 7.0.1-2 makes an
    incorrect function call in attempting to locate the
    next token, which allows remote attackers to cause a
    denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted file.(CVE-2016-4564 )The ReadCINImage function
    in coders/cin.c in ImageMagick before 6.9.9-0 and 7.x
    before 7.0.6-1 allows remote attackers to cause a
    denial of service (memory consumption) via a crafted
    file.(CVE-2017-11525)In coders/bmp.c in ImageMagick
    before 7.0.8-16, an input file can result in an
    infinite loop and hang, with high CPU and memory
    consumption. Remote attackers could leverage this
    vulnerability to cause a denial of service via a
    crafted file.(CVE-2018-20467)coders/pnm.c in
    ImageMagick 6.9.0-1 Beta and earlier allows remote
    attackers to cause a denial of service (crash) via a
    crafted png file.(CVE-2014-9837)coders/sun.c in
    ImageMagick before 6.9.0-4 Beta allows remote attackers
    to cause a denial of service (out-of-bounds read and
    application crash) via a crafted SUN
    file.(CVE-2015-8958)Memory leak in the ReadPSDLayers
    function in coders/psd.c in ImageMagick before 6.9.6-3
    allows remote attackers to cause a denial of service
    (memory consumption) via a crafted image
    file.(CVE-2016-10058)The MSL interpreter in ImageMagick
    before 6.9.6-4 allows remote attackers to cause a
    denial of service (segmentation fault and application
    crash) via a crafted XML file.(CVE-2016-10068)The
    ReadDCMImage function in DCM reader in ImageMagick
    before 6.9.4-5 and 7.x before 7.0.1-7 allows remote
    attackers to have unspecified impact via vectors
    involving the for statement in computing the pixel
    scaling table.(CVE-2016-5690)Heap-based buffer overflow
    in coders/hdr.c in ImageMagick allows remote attackers
    to cause a denial of service (out-of-bounds read) via a
    crafted HDR file.(CVE-2016-7520)MagickCore/profile.c in
    ImageMagick before 7.0.3-2 allows remote attackers to
    cause a denial of service (out-of-bounds read) via a
    crafted file.(CVE-2016-7799)The ReadOneMNGImage
    function in coders/png.c in ImageMagick before 6.9.9-0
    and 7.x before 7.0.6-1 allows remote attackers to cause
    a denial of service (large loop and CPU consumption)
    via a crafted file.(CVE-2017-11526)In ImageMagick
    before 6.9.7-6 and 7.x before 7.0.4-6, the ReadMATImage
    function in coders/mat.c uses uninitialized data, which
    might allow remote attackers to obtain sensitive
    information from process
    memory.(CVE-2017-13143)coders/psd.c in ImageMagick
    allows remote attackers to have unspecified impact via
    a crafted PSD file, which triggers an out-of-bounds
    write.(CVE-2017-5510)In the ReadDCMImage function in
    coders/dcm.c in ImageMagick before 7.0.7-23, each
    redmap, greenmap, and bluemap variable can be
    overwritten by a new pointer. The previous pointer is
    lost, which leads to a memory leak. This allows remote
    attackers to cause a denial of
    service.(CVE-2018-6405)Heap-based buffer overflow in
    ImageMagick allows remote attackers to have unspecified
    impact via a crafted psd file, a different
    vulnerability than CVE-2014-9824.(CVE-2014-9825)Buffer
    overflow in ImageMagick before 6.9.0-4 Beta allows
    remote attackers to cause a denial of service
    (application crash) via a crafted SUN
    file.(CVE-2015-8957)Buffer overflow in the
    WriteGROUP4Image function in coders/tiff.c in
    ImageMagick before 6.9.5-8 allows remote attackers to
    cause a denial of service (application crash) or have
    other unspecified impact via a crafted
    file.(CVE-2016-10057)magick/memory.c in ImageMagick
    before 6.9.4-5 allows remote attackers to cause a
    denial of service (application crash) via vectors
    involving 'too many exceptions,' which trigger a buffer
    overflow.(CVE-2016-10067)The DCM reader in ImageMagick
    before 6.9.4-5 and 7.x before 7.0.1-7 allows remote
    attackers to have unspecified impact by leveraging lack
    of NULL pointer checks.(CVE-2016-5689)The ReadRLEImage
    function in coders/rle.c in ImageMagick allows remote
    attackers to cause a denial of service (out-of-bounds
    read) via a crafted file.(CVE-2016-7519)Memory leak in
    AcquireVirtualMemory in ImageMagick before 7 allows
    remote attackers to cause a denial of service (memory
    consumption) via unspecified vectors.(CVE-2016-7539)The
    WriteBlob function in MagickCore/blob.c in ImageMagick
    before 6.9.8-10 and 7.x before 7.6.0-0 allows remote
    attackers to cause a denial of service (assertion
    failure and application exit) via a crafted
    file.(CVE-2017-11524)In ImageMagick before 6.9.9-0 and
    7.x before 7.0.6-1, a crafted PNG file could trigger a
    crash because there was an insufficient check for short
    files.(CVE-2017-13142)coders/psd.c in ImageMagick
    allows remote attackers to have unspecified impact via
    a crafted PSD file, which triggers an out-of-bounds
    write.(CVE-2017-5509)The ReadSVGImage function in svg.c
    in ImageMagick 7.0.5-4 allows remote attackers to
    consume an amount of available memory via a crafted
    file.(CVE-2017-7943)Heap-based buffer overflow in
    ImageMagick allows remote attackers to have unspecified
    impact via a crafted psd file, a different
    vulnerability than CVE-2014-9825.(CVE-2014-9824)The
    ReadVICARImage function in coders/vicar.c in
    ImageMagick 6.x before 6.9.0-5 Beta allows remote
    attackers to cause a denial of service (infinite loop)
    via a crafted VICAR file.(CVE-2015-8903)Buffer overflow
    in the sixel_decode function in coders/sixel.c in
    ImageMagick before 6.9.5-8 allows remote attackers to
    cause a denial of service (application crash) or have
    other unspecified impact via a crafted
    file.(CVE-2016-10056)Buffer overflow in the
    ReadVIFFImage function in coders/viff.c in ImageMagick
    before 6.9.4-5 allows remote attackers to cause a
    denial of service (application crash) via a crafted
    file.(CVE-2016-10066)The WPG parser in ImageMagick
    before 6.9.4-4 and 7.x before 7.0.1-5, when a memory
    limit is set, allows remote attackers to have
    unspecified impact via vectors related to the
    SetImageExtent return-value check, which trigger (1) a
    heap-based buffer overflow in the SetPixelIndex
    function or an invalid write operation in the (2)
    ScaleCharToQuantum or (3) SetPixelIndex
    functions.(CVE-2016-5688)The ReadSUNImage function in
    coders/sun.c in ImageMagick allows remote attackers to
    cause a denial of service (out-of-bounds read) via a
    crafted SUN file.(CVE-2016-7518)The generic decoder in
    ImageMagick allows remote attackers to cause a denial
    of service (out-of-bounds access) via a crafted
    file.(CVE-2016-7534)The ReadTXTImage function in
    coders/txt.c in ImageMagick through 6.9.9-0 and 7.x
    through 7.0.6-1 allows remote attackers to cause a
    denial of service (infinite loop) via a crafted file,
    because the end-of-file condition is not
    considered.(CVE-2017-11523)In ImageMagick before
    6.9.9-4 and 7.x before 7.0.6-4, a crafted file could
    trigger a memory leak in ReadOnePNGImage in
    coders/png.c.(CVE-2017-13141)Heap-based buffer overflow
    in the PushQuantumPixel function in ImageMagick before
    6.9.7-3 and 7.x before 7.0.4-3 allows remote attackers
    to cause a denial of service (application crash) via a
    crafted TIFF file.(CVE-2017-5508)The ReadAVSImage
    function in avs.c in ImageMagick 7.0.5-4 allows remote
    attackers to consume an amount of available memory via
    a crafted file.(CVE-2017-7942)Heap-based buffer
    overflow in ImageMagick allows remote attackers to have
    unspecified impact via a crafted palm file, a different
    vulnerability than CVE-2014-9819.(CVE-2014-9823)The
    ReadBlobByte function in coders/pdb.c in ImageMagick
    6.x before 6.9.0-5 Beta allows remote attackers to
    cause a denial of service (infinite loop) via a crafted
    PDB file.(CVE-2015-8902)Buffer overflow in the
    WritePDBImage function in coders/pdb.c in ImageMagick
    before 6.9.5-8 allows remote attackers to cause a
    denial of service (application crash) or have other
    unspecified impact via a crafted
    file.(CVE-2016-10055)The ReadVIFFImage function in
    coders/viff.c in ImageMagick before 7.0.1-0 allows
    remote attackers to cause a denial of service
    (application crash) or have other unspecified impact
    via a crafted file.(CVE-2016-10065)The VerticalFilter
    function in the DDS coder in ImageMagick before 6.9.4-3
    and 7.x before 7.0.1-4 allows remote attackers to have
    unspecified impact via a crafted DDS file, which
    triggers an out-of-bounds read.(CVE-2016-5687)The
    EncodeImage function in coders/pict.c in ImageMagick
    allows remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted PICT
    file.(CVE-2016-7517)The ReadWPGImage function in
    coders/wpg.c in ImageMagick allows remote attackers to
    cause a denial of service (out-of-bounds read) via a
    crafted WPG file.(CVE-2016-7533)The ReadOneJNGImage
    function in coders/png.c in ImageMagick through 6.9.9-0
    and 7.x through 7.0.6-1 allows remote attackers to
    cause a denial of service (large loop and CPU
    consumption) via a malformed JNG
    file.(CVE-2017-11505)In ImageMagick before 6.9.9-1 and
    7.x before 7.0.6-2, the ReadOnePNGImage function in
    coders/png.c allows remote attackers to cause a denial
    of service (application hang in LockSemaphoreInfo) via
    a PNG file with a width equal to
    MAGICK_WIDTH_LIMIT.(CVE-2017-13140)Memory leak in
    coders/mpc.c in ImageMagick before 6.9.7-4 and 7.x
    before 7.0.4-4 allows remote attackers to cause a
    denial of service (memory consumption) via vectors
    involving a pixel cache.(CVE-2017-5507)The ReadSGIImage
    function in sgi.c in ImageMagick 7.0.5-4 allows remote
    attackers to consume an amount of available memory via
    a crafted file.(CVE-2017-7941)Heap-based buffer
    overflow in ImageMagick allows remote attackers to have
    unspecified impact via a crafted quantum
    file.(CVE-2014-9822)ImageMagick 6.x before 6.9.0-5 Beta
    allows remote attackers to cause a denial of service
    (infinite loop) via a crafted MIFF
    file.(CVE-2015-8901)Buffer overflow in the
    WriteMAPImage function in coders/map.c in ImageMagick
    before 6.9.5-8 allows remote attackers to cause a
    denial of service (application crash) or have other
    unspecified impact via a crafted
    file.(CVE-2016-10054)Buffer overflow in coders/tiff.c
    in ImageMagick before 6.9.5-1 allows remote attackers
    to cause a denial of service (application crash) or
    have other unspecified impact via a crafted
    file.(CVE-2016-10064)Memory leak in the IsOptionMember
    function in MagickCore/option.c in ImageMagick before
    6.9.2-2, as used in ODR-PadEnc and other products,
    allows attackers to trigger memory
    consumption.(CVE-2016-10252)The ReadVIFFImage function
    in coders/viff.c in ImageMagick allows remote attackers
    to cause a denial of service (out-of-bounds read) via a
    crafted VIFF file.(CVE-2016-7516)MagickCore/memory.c in
    ImageMagick allows remote attackers to cause a denial
    of service (out-of-bounds write) via a crafted PDB
    file.(CVE-2016-7531)The ReadOneDJVUImage function in
    coders/djvu.c in ImageMagick through 6.9.9-0 and 7.x
    through 7.0.6-1 allows remote attackers to cause a
    denial of service (infinite loop and CPU consumption)
    via a malformed DJVU image.(CVE-2017-11478)In
    ImageMagick before 6.9.9-0 and 7.x before 7.0.6-1, the
    ReadOneMNGImage function in coders/png.c has an
    out-of-bounds read with the MNG CLIP
    chunk.(CVE-2017-13139)ImageMagick before 7.0.7-12 has a
    coders/png.c Magick_png_read_raw_profile heap-based
    buffer over-read via a crafted file, related to
    ReadOneMNGImage.(CVE-2017-17504)An issue was discovered
    in ImageMagick 6.9.7. A specially crafted webp file
    could lead to a file-descriptor leak in libmagickcore
    (thus, a DoS).(CVE-2017-6502)Heap-based buffer overflow
    in ImageMagick allows remote attackers to have
    unspecified impact via a crafted xpm
    file.(CVE-2014-9821)The ReadHDRImage function in
    coders/hdr.c in ImageMagick 6.x and 7.x allows remote
    attackers to cause a denial of service (infinite loop)
    via a crafted HDR file.(CVE-2015-8900)The
    WriteTIFFImage function in coders/tiff.c in ImageMagick
    before 6.9.5-8 allows remote attackers to cause a
    denial of service (divide-by-zero error and application
    crash) via a crafted file.(CVE-2016-10053)Buffer
    overflow in coders/tiff.c in ImageMagick before 6.9.5-1
    allows remote attackers to cause a denial of service
    (application crash) or have other unspecified impact
    via a crafted file, related to extend
    validity.(CVE-2016-10063)Off-by-one error in
    coders/wpg.c in ImageMagick allows remote attackers to
    have unspecified impact via vectors related to a string
    copy.(CVE-2016-10145)The ReadRLEImage function in
    coders/rle.c in ImageMagick allows remote attackers to
    cause a denial of service (out-of-bounds read) via
    vectors related to the number of
    pixels.(CVE-2016-7515)The quantum handling code in
    ImageMagick allows remote attackers to cause a denial
    of service (divide-by-zero error or out-of-bounds
    write) via a crafted file.(CVE-2016-7530)coders/tiff.c
    in ImageMagick before 7.0.3.7 allows remote attackers
    to cause a denial of service (NULL pointer dereference
    and crash) via a crafted image.(CVE-2016-9559)The
    ProcessMSLScript function in coders/msl.c in
    ImageMagick before 6.9.9-5 and 7.x before 7.0.6-5
    allows remote attackers to cause a denial of service
    (memory leak) via a crafted file, related to the
    WriteMSLImage function.(CVE-2017-12427)ImageMagick
    before 6.9.9-24 and 7.x before 7.0.7-12 has a
    use-after-free in Magick::Image::read in
    Magick++/lib/Image.cpp.(CVE-2017-17499)An issue was
    discovered in ImageMagick 6.9.7. A specially crafted
    xcf file could lead to a NULL pointer
    dereference.(CVE-2017-6501)The JPEG decoder in
    ImageMagick before 6.8.9-9 allows local users to cause
    a denial of service (out-of-bounds memory access and
    crash).(CVE-2014-8716)coders/dds.c in ImageMagick
    allows remote attackers to cause a denial of service
    via a crafted DDS file.(CVE-2014-9907)Buffer overflow
    in the WriteProfile function in coders/jpeg.c in
    ImageMagick before 6.9.5-6 allows remote attackers to
    cause a denial of service (application crash) or have
    other unspecified impact via a crafted
    file.(CVE-2016-10052)The ReadGROUP4Image function in
    coders/tiff.c in ImageMagick does not check the return
    value of the fwrite function, which allows remote
    attackers to cause a denial of service (application
    crash) via a crafted file.(CVE-2016-10062)coders/ipl.c
    in ImageMagick allows remote attackers to have
    unspecific impact by leveraging a missing malloc
    check.(CVE-2016-10144)The SGI coder in ImageMagick
    before 7.0.2-10 allows remote attackers to cause a
    denial of service (out-of-bounds read) via a large row
    value in an sgi file.(CVE-2016-7101)coders/xcf.c in
    ImageMagick allows remote attackers to cause a denial
    of service (out-of-bounds read) via a crafted XCF
    file.(CVE-2016-7529)The AcquireMagickMemory function in
    MagickCore/memory.c in ImageMagick 7.0.3.3 before
    7.0.3.8 allows remote attackers to have unspecified
    impact via a crafted image, which triggers a memory
    allocation failure. NOTE: this vulnerability exists
    because of an incomplete fix for
    CVE-2016-8862.(CVE-2016-8866)The ReadEPTImage function
    in coders/ept.c in ImageMagick before 6.9.9-0 and 7.x
    before 7.0.6-1 allows remote attackers to cause a
    denial of service (memory consumption) via a crafted
    file.(CVE-2017-11530)In ImageMagick before 6.9.9-3 and
    7.x before 7.0.6-3, there is a missing NULL check in
    the ReadMATImage function in coders/mat.c, leading to a
    denial of service (assertion failure and application
    exit) in the DestroyImageInfo function in
    MagickCore/image.c.(CVE-2017-13658)An issue was
    discovered in ImageMagick 6.9.7. A specially crafted
    sun file triggers a heap-based buffer
    over-read.(CVE-2017-6500)DCM decode in ImageMagick
    before 6.8.9-9 allows remote attackers to cause a
    denial of service (out-of-bounds
    read).(CVE-2014-8562)coders/tiff.c in ImageMagick
    allows remote attackers to cause a denial of service
    (application crash) via vectors related to the
    'identification of image.'(CVE-2014-9854)Buffer
    overflow in the ReadRLEImage function in coders/rle.c
    in ImageMagick before 6.9.4-4 allows remote attackers
    to cause a denial of service (application crash) or
    have other unspecified impact via a crafted RLE
    file.(CVE-2016-10049)The ReadGROUP4Image function in
    coders/tiff.c in ImageMagick before 7.0.1-10 does not
    check the return value of the fputc function, which
    allows remote attackers to cause a denial of service
    (crash) via a crafted image
    file.(CVE-2016-10061)coders/mat.c in ImageMagick before
    6.9.4-0 allows remote attackers to cause a denial of
    service (out-of-bounds read and application crash) via
    a crafted mat file.(CVE-2016-10071)Integer overflow in
    the BMP coder in ImageMagick before 7.0.2-10 allows
    remote attackers to cause a denial of service (crash)
    via crafted height and width values, which triggers an
    out-of-bounds write.(CVE-2016-6823)The ReadVIFFImage
    function in coders/viff.c in ImageMagick allows remote
    attackers to cause a denial of service (segmentation
    fault) via a crafted VIFF file.(CVE-2016-7528)An
    exploitable out of bounds write exists in the handling
    of compressed TIFF images in ImageMagicks's convert
    utility. A crafted TIFF document can lead to an out of
    bounds write which in particular circumstances could be
    leveraged into remote code execution. The vulnerability
    can be triggered through any user controlled TIFF that
    is handled by this functionality.(CVE-2016-8707)The
    ReadMATImage function in coders/mat.c in ImageMagick
    before 6.9.9-0 and 7.x before 7.0.6-1 allows remote
    attackers to cause a denial of service (memory leak)
    via a crafted file.(CVE-2017-11529)In ImageMagick
    before 6.9.8-5 and 7.x before 7.0.5-6, there is a
    memory leak in the ReadMATImage function in
    coders/mat.c.(CVE-2017-13146)An issue was discovered in
    Magick++ in ImageMagick 6.9.7. A specially crafted file
    creating a nested exception could lead to a memory leak
    (thus, a DoS).(CVE-2017-6499)PCX parser code in
    ImageMagick before 6.8.9-9 allows remote attackers to
    cause a denial of service (out-of-bounds
    read).(CVE-2014-8355)Memory leak in coders/rle.c in
    ImageMagick allows remote attackers to cause a denial
    of service (memory consumption) via a crafted rle
    file.(CVE-2014-9853)Memory leak in the NewXMLTree
    function in magick/xml-tree.c in ImageMagick before
    6.9.4-7 allows remote attackers to cause a denial of
    service (memory consumption) via a crafted XML
    file.(CVE-2016-10047)The ConcatenateImages function in
    MagickWand/magick-cli.c in ImageMagick before 7.0.1-10
    does not check the return value of the fputc function,
    which allows remote attackers to cause a denial of
    service (application crash) via a crafted
    file.(CVE-2016-10060)Heap-based buffer overflow in the
    CalcMinMax function in coders/mat.c in ImageMagick
    before 6.9.4-0 allows remote attackers to cause a
    denial of service (out-of-bounds read and application
    crash) via a crafted mat file.(CVE-2016-10070)Buffer
    overflow in the Get8BIMProperty function in
    MagickCore/property.c in ImageMagick before 6.9.5-4 and
    7.x before 7.0.2-6 allows remote attackers to cause a
    denial of service (out-of-bounds read, memory leak, and
    crash) via a crafted image.(CVE-2016-6491)coders/wpg.c
    in ImageMagick allows remote attackers to cause a
    denial of service (out-of-bounds write) via a crafted
    file.(CVE-2016-7526)The AcquireQuantumPixels function
    in MagickCore/quantum.c in ImageMagick before 7.0.3-1
    allows remote attackers to have unspecified impact via
    a crafted image file, which triggers a memory
    allocation failure.(CVE-2016-8677)The ReadDIBImage
    function in coders/dib.c in ImageMagick before 6.9.9-0
    and 7.x before 7.0.6-1 allows remote attackers to cause
    a denial of service (memory leak) via a crafted
    file.(CVE-2017-11528)In ImageMagick before 6.9.8-8 and
    7.x before 7.0.5-9, the ReadJP2Image function in
    coders/jp2.c does not properly validate the channel
    geometry, leading to a crash.(CVE-2017-13145)An issue
    was discovered in ImageMagick 6.9.7. Incorrect TGA
    files could trigger assertion failures, thus leading to
    DoS.(CVE-2017-6498)The HorizontalFilter function in
    resize.c in ImageMagick before 6.8.9-9 allows remote
    attackers to cause a denial of service (out-of-bounds
    read) via a crafted image
    file.(CVE-2014-8354)distribute-cache.c in ImageMagick
    re-uses objects after they have been destroyed, which
    allows remote attackers to have unspecified impact via
    unspecified vectors.(CVE-2014-9852)Heap-based buffer
    overflow in the DrawImage function in magick/draw.c in
    ImageMagick before 6.9.5-5 allows remote attackers to
    cause a denial of service (application crash) via a
    crafted image file.(CVE-2016-10046)Buffer overflow in
    coders/tiff.c in ImageMagick before 6.9.4-1 allows
    remote attackers to cause a denial of service
    (application crash) or have unspecified other impact
    via a crafted TIFF file.(CVE-2016-10059)coders/mat.c in
    ImageMagick before 6.9.4-5 allows remote attackers to
    cause a denial of service (application crash) via a mat
    file with an invalid number of
    frames.(CVE-2016-10069)The DCM reader in ImageMagick
    before 6.9.4-5 and 7.x before 7.0.1-7 allows remote
    attackers to have unspecified impact by leveraging lack
    of validation of (1) pixel.red, (2) pixel.green, and
    (3) pixel.blue.(CVE-2016-5691)Heap-based buffer
    overflow in coders/psd.c in ImageMagick allows remote
    attackers to cause a denial of service (out-of-bounds
    read) via a crafted PSD
    file.(CVE-2016-7525)magick/attribute.c in ImageMagick
    7.0.3-2 allows remote attackers to cause a denial of
    service (use-after-free) via a crafted
    file.(CVE-2016-7906)The ReadDPXImage function in
    coders/dpx.c in ImageMagick before 6.9.9-0 and 7.x
    before 7.0.6-1 allows remote attackers to cause a
    denial of service (memory consumption) via a crafted
    file.(CVE-2017-11527)In ImageMagick before 6.9.7-10,
    there is a crash (rather than a 'width or height
    exceeds limit' error report) if the image dimensions
    are too large, as demonstrated by use of the mpc
    coder.(CVE-2017-13144)An issue was discovered in
    ImageMagick 6.9.7. A specially crafted psd file could
    lead to a NULL pointer dereference (thus, a
    DoS).(CVE-2017-6497)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2354
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aef7cdc");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16328");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["ImageMagick-6.9.9.38-1.h4",
        "ImageMagick-c++-6.9.9.38-1.h4",
        "ImageMagick-libs-6.9.9.38-1.h4",
        "ImageMagick-perl-6.9.9.38-1.h4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
