#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K35155453.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(94647);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9655", "CVE-2015-8665", "CVE-2015-8683", "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783");
  script_bugtraq_id(72323, 72352, 72353, 73441);

  script_name(english:"F5 Networks BIG-IP : Multiple LibTIFF vulnerabilities (K35155453)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2015-8683

The putcontig8bitCIELab function in tif_getimage.c in LibTIFF 4.0.6
allows remote attackers to cause a denial of service (out-of-bounds
read) via a packed TIFF image.

CVE-2015-8665 tif_getimage.c in LibTIFF 4.0.6 allows remote attackers
to cause a denial of service (out-of-bounds read) via the
SamplesPerPixel tag in a TIFF image.

CVE-2014-8129 LibTIFF 4.0.3 allows remote attackers to cause a denial
of service (out-of-bounds write) or possibly have unspecified other
impact via a crafted TIFF image, as demonstrated by failure of
tif_next.c to verify that the BitsPerSample value is 2, and the
t2p_sample_lab_signed_to_unsigned function in tiff2pdf.c.

CVE-2014-8130 The _TIFFmalloc function in tif_unix.c in LibTIFF 4.0.3
does not reject a zero size, which allows remote attackers to cause a
denial of service (divide-by-zero error and application crash) via a
crafted TIFF image that is mishandled by the TIFFWriteScanline
function in tif_write.c, as demonstrated by tiffdither.

CVE-2014-8127 LibTIFF 4.0.3 allows remote attackers to cause a denial
of service (out-of-bounds read and crash) via a crafted TIFF image to
the (1) checkInkNamesString function in tif_dir.c in the thumbnail
tool, (2) compresscontig function in tiff2bw.c in the tiff2bw tool,
(3) putcontig8bitCIELab function in tif_getimage.c in the tiff2rgba
tool, LZWPreDecode function in tif_lzw.c in the (4) tiff2ps or (5)
tiffdither tool, (6) NeXTDecode function in tif_next.c in the
tiffmedian tool, or (7) TIFFWriteDirectoryTagLongLong8Array function
in tif_dirwrite.c in the tiffset tool.

CVE-2014-9655 The (1) putcontig8bitYCbCr21tile function in
tif_getimage.c or (2) NeXTDecode function in tif_next.c in LibTIFF
allows remote attackers to cause a denial of service (uninitialized
memory access) via a crafted TIFF image, as demonstrated by
libtiff-cvs-1.tif and libtiff-cvs-2.tif.

CVE-2015-8781 tif_luv.c in libtiff allows attackers to cause a denial
of service (out-of-bounds write) via an invalid number of samples per
pixel in a LogL compressed TIFF image, a different vulnerability than
CVE-2015-8782.

CVE-2015-8782 tif_luv.c in libtiff allows attackers to cause a denial
of service (out-of-bounds writes) via a crafted TIFF image, a
different vulnerability than CVE-2015-8781.

CVE-2015-8783 tif_luv.c in libtiff allows attackers to cause a denial
of service (out-of-bounds reads) via a crafted TIFF image.

Impact

An attacker can use specially crafted TIFF files to execute arbitrary
code with the limited privileges of the image optimization process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K35155453"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K35155453."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K35155453";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0-12.1.2","11.4.0-11.6.1");
vmatrix["AM"]["unaffected"] = make_list("13.0.0");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.2.1");
vmatrix["WAM"]["unaffected"] = make_list("10.2.1-10.2.4");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_warning(port:0, extra:bigip_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules AM / WAM");
}
