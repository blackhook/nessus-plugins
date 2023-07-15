#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K34527393.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(105404);
  script_version("3.5");
  script_cvs_date("Date: 2019/01/04 10:03:41");

  script_cve_id("CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535");

  script_name(english:"F5 Networks BIG-IP : LibTIFF vulnerabilities (K34527393)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-9533 tif_pixarlog.c in libtiff 4.0.6 has out-of-bounds write
vulnerabilities in heap allocated buffers. Reported as MSVR 35094, aka
'PixarLog horizontalDifference heap-buffer-overflow.'

CVE-2016-9534 tif_write.c in libtiff 4.0.6 has an issue in the error
code path of TIFFFlushData1() that didn't reset the tif_rawcc and
tif_rawcp members. Reported as MSVR 35095, aka 'TIFFFlushData1
heap-buffer-overflow.'

CVE-2016-9535 tif_predict.h and tif_predict.c in libtiff 4.0.6 have
assertions that can lead to assertion failures in debug mode, or
buffer overflows in release mode, when dealing with unusual tile size
like YCbCr with subsampling. Reported as MSVR 35105, aka 'Predictor
heap-buffer-overflow.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K34527393"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K34527393."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K34527393";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2","11.4.0-11.6.1");
vmatrix["AM"]["unaffected"] = make_list("13.1.0","13.0.1","12.1.3");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running the affected module AM");
}
