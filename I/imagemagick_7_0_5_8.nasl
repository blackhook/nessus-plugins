#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100847);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2017-7606",
    "CVE-2017-7619",
    "CVE-2017-7941",
    "CVE-2017-7942",
    "CVE-2017-7943",
    "CVE-2017-8343",
    "CVE-2017-8344",
    "CVE-2017-8345",
    "CVE-2017-8346",
    "CVE-2017-8347",
    "CVE-2017-8348",
    "CVE-2017-8349",
    "CVE-2017-8350",
    "CVE-2017-8351",
    "CVE-2017-8352",
    "CVE-2017-8353",
    "CVE-2017-8354",
    "CVE-2017-8355",
    "CVE-2017-8356",
    "CVE-2017-8357",
    "CVE-2017-8765",
    "CVE-2017-8830",
    "CVE-2017-9098",
    "CVE-2017-9141",
    "CVE-2017-9142",
    "CVE-2017-9143",
    "CVE-2017-9144",
    "CVE-2017-9261",
    "CVE-2017-9262",
    "CVE-2017-9405",
    "CVE-2017-9407",
    "CVE-2017-9409",
    "CVE-2017-9439",
    "CVE-2017-9440",
    "CVE-2017-9500"
  );
  script_bugtraq_id(
    97944,
    97946,
    97956,
    98132,
    98136,
    98138,
    98346,
    98363,
    98364,
    98370,
    98371,
    98372,
    98373,
    98374,
    98377,
    98378,
    98380,
    98388,
    98593,
    98603,
    98606,
    98682,
    98683,
    98685,
    98687,
    98688,
    98689,
    98730,
    98735,
    98907,
    98908,
    98941
  );

  script_name(english:"ImageMagick 6.x < 6.9.8-10 / 7.x < 7.0.5-9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.8-10 or 7.x prior to 7.0.5-9. It is, therefore, affected
by multiple vulnerabilities :

  - A flaw exists in the ReadRLEImage() function within file
    coders/rle.c when reading image color maps due to issues
    related to a 'type unsigned char' falling outside the
    range of representable values. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted image, to cause a denial of service condition or
    possibly have other impact. (CVE-2017-7606)

  - An infinite loop condition exists in multiple color
    algorithms within file magick/enhance.c due to a
    floating-point rounding error. An unauthenticated,
    remote attacker can exploit this to consume excessive
    resources, resulting in a denial of service condition.
    (CVE-2017-7619)

  - A denial of service vulnerability exists in the
    ReadSGIImage() function within file coders/sgi.c when
    handling a specially crafted file. An unauthenticated,
    remote attacker can exploit this to consume excessive
    memory resources. (CVE-2017-7941)

  - A denial of service vulnerability exists in the
    ReadAVSImage() function within file coders/avs.c when
    handling a specially crafted file. An unauthenticated,
    remote attacker can exploit this to consume excessive
    memory resources. (CVE-2017-7942)

  - A denial of service vulnerability exists in the
    ReadSVGImage() function within file coders/svg.c when
    handling a specially crafted file. An unauthenticated,
    remote attacker can exploit this to consume excessive
    memory resources. (CVE-2017-7943)

  - A denial of service vulnerability exists in the
    ReadAAIImage() function within file aai.c when handling
    specially crafted AAI files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8343)

  - A denial of service vulnerability exists in the
    ReadPCXImage() function within file pcx.c when handling
    specially crafted DCX files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8344)

  - A denial of service vulnerability exists in the
    ReadMNGImage() function within file png.c when handling
    specially crafted MNG files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8345)

  - A denial of service vulnerability exists in the
    ReadDCMImage() function within file dcm.c when handling
    specially crafted DCM files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8346)

  - A denial of service vulnerability exists in the
    ReadEXRImage() function within file exr.c when handling
    specially crafted EXR files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8347)

  - A denial of service vulnerability exists in the
    ReadMATImage() function within file mat.c when handling
    specially crafted MAT files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8348)

  - A denial of service vulnerability exists in the
    ReadSFWImage() function within file sfw.c when handling
    specially crafted SFW files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8349)

  - A denial of service vulnerability exists in the
    ReadJNGImage() function within file png.c when handling
    specially crafted JNG files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8350)

  - A denial of service vulnerability exists in the
    ReadPCDImage() function within file pcd.c when handling
    specially crafted PCD files. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8351)

  - A denial of service vulnerability exists in the
    ReadXWDImage() function within file coders/xwd.c when
    parsing XWD images. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to
    consume excessive memory resources. (CVE-2017-8352)

  - A denial of service vulnerability exists in the
    ReadPICTImage() function within file coders/pict.c when
    parsing PICT images. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to
    consume excessive memory resources. (CVE-2017-8353)

  - A denial of service vulnerability exists in the
    ReadBMPImage() function within file coders/bmp.c when
    parsing BMP images. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to
    consume excessive memory resources. (CVE-2017-8354)

  - A denial of service vulnerability exists in the
    ReadMTVImage() function within file coders/mtv.c when
    parsing MTV images. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to
    consume excessive memory resources. (CVE-2017-8355)

  - A denial of service vulnerability exists in the
    ReadSUNImage() function within file coders/sun.c when
    parsing SUN images. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to
    consume excessive memory resources. (CVE-2017-8356)

  - A denial of service vulnerability exists in the
    ReadEPTImage() function within file coders/ept.c when
    parsing EPT images. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to
    consume excessive memory resources. (CVE-2017-8357)

  - A denial of service vulnerability exists in the
    ReadICONImage() function within file coders/icon.c when
    parsing ICON files. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to
    consume excessive memory resources. (CVE-2017-8765)

  - A denial of service vulnerability exists in the
    ReadBMPImage() function within file bmp.c when handling
    a specially crafted file. An unauthenticated, remote
    attacker can exploit this to consume excessive memory
    resources. (CVE-2017-8830)

  - An out-of-bounds read error exists in the ReadRLEImage()
    function within file coders/rle.c when handling image
    color maps due to a missing initialization step. An
    unauthenticated, remote attacker can exploit this to
    disclose process memory contents. (CVE-2017-9098)

  - A denial of service vulnerability exists in the
    ReadDDSImage() function within file coders/dds.c when
    handling DDS images due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to trigger an assertion failure.
    (CVE-2017-9141)

  - A denial of service vulnerability exists in the
    ReadOneJNGImage() function within file coders/png.c when
    handling JNG images due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to trigger an assertion failure.
    (CVE-2017-9142)

  - A denial of service vulnerability exists in the
    ReadARTImage() function within file coders/art.c when
    handling specially crafted ART files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9143)

  - A flaw exists in the ReadRLEImage() function within file
    coders/rle.c when reading run-length encoded image data.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted image files, to cause a denial of
    service condition. (CVE-2017-9144)

  - A denial of service vulnerability exists in the
    ReadOneMNGImage() function within file coders/png.c when
    handling specially crafted MNG files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9261)

  - A denial of service vulnerability exists in the
    ReadOneJNGImage() function within file coders/png.c when
    handling specially crafted JNG files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9262)

  - A denial of service vulnerability exists in the
    ReadICONImage() function within file coders/icon.c when
    handling specially crafted ICO files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9405)

  - A denial of service vulnerability exists in the
    ReadPALMImage() function within file coders/palm.c when
    handling specially crafted PALM files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9407)

  - A denial of service vulnerability exists in the
    ReadMPCImage() function within file coders/mpc.c when
    handling specially crafted MPC files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9409)

  - A denial of service vulnerability exists in the
    ReadPDBImage() function within file coders/pdb.c when
    handling specially crafted PDB files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9439)

  - A denial of service vulnerability exists in the
    ReadPSDChannelZip() function within file coders/psd.c
    when handling specially crafted PSD files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9440)

  - A denial of service vulnerability exists in the
    ResetImageProfileIterator() function within file 
    coders/dds.c when handling specially crafted DDS images.
    An unauthenticated, remote attacker can exploit this to
    consume excessive memory resources. (CVE-2017-9500)

  - A denial of service vulnerability exists in the
    ReadTGAImage() function within file coders/tga.c when
    handling specially crafted VST files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources.

  - A denial of service vulnerability exists in the
    RestoreMSCWarning() function within file coders/mat.c
    when handling specially crafted MAT files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources.

  - A denial of service vulnerability exists in the
    ReadXWDImage() function within file coders/xwd.c
    when handling specially crafted XWD files. An
    unauthenticated, remote attacker can exploit this to
    consume excessive memory resources.

  - A flaw exists in the ReadDCMImage() function within file
    coders/dcm.c when handling DCM image color maps. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted image, to cause a denial of service
    condition.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2017/May/63");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2017/dsa-3863");
  script_set_attribute(attribute:"see_also", value:"https://usn.ubuntu.com/3302-1/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.8-10 / 7.0.5-9 or later. Note that
you may also need to manually uninstall the vulnerable version from
the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9098");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick", "installed_sw/ImageMagick/vcf_version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
app_info = vcf::imagemagick::get_app_info();

constraints = [
  {'min_version' : '6.0.0-0' , 'fixed_version' : '6.9.8-10'},
  {'min_version' : '7.0.0-0' , 'fixed_version' : '7.0.5-9'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
