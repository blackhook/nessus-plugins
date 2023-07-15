#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K89096577.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(94648);
  script_version("2.14");
  script_cvs_date("Date: 2019/01/04 10:03:40");

  script_cve_id("CVE-2015-8784", "CVE-2016-5314", "CVE-2016-5320");

  script_name(english:"F5 Networks BIG-IP : LibTIFF vulnerabilities (K89096577)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-5314

Buffer overflow in the PixarLogDecode function in tif_pixarlog.c in
LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact
via a crafted TIFF image, as demonstrated by overwriting the
vgetparent function pointer with rgb2ycbcr.

Note : This was previously referenced as CVE-2016-5320. All CVE users
should reference CVE-2016-5314 instead of CVE-2016-5320.

CVE-2015-8784 The NeXTDecode function in tif_next.c in LibTIFF allows
remote attackers to cause a denial of service (out-of-bounds write)
via a crafted TIFF image, as demonstrated by libtiff5.tif.

Impact

An attacker can use specially crafted TIFF files to execute arbitrary
code with the limited privileges of the image optimization process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K89096577"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K89096577."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sol = "K89096577";
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
