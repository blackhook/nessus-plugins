#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(166684);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/28");

  script_name(english:"VMware NSX For vSphere (NSX-v) Unsupported Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is no longer supported.");

  script_set_attribute(attribute:"description", value:
"The VMware NSX for vSphere (NSX-v) appliance is no longer supported.

Lack of support implies that no security patches for the product will
be released by the vendor.  As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/85706");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor for more information.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:vmware:nsx-v");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:vmware:nsx_for_vsphere");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_nsx_for_vsphere_web_detect.nbin");
  script_require_keys("installed_sw/VMware NSX for vSphere (NSX-v)");

  exit(0);
}

var app = 'VMware NSX for vSphere (NSX-v)';

if (!get_kb_item('installed_sw/' + app)) 
  audit(AUDIT_HOST_NOT, app);

register_unsupported_product(
  product_name  : app,
  cpe_base      : 'vmware:nsx-v',
  cpe_class     : CPE_CLASS_HARDWARE,
  is_custom_cpe : true
);

var ordered_fields = [ 'Product', 'End of support date' ];
var report_items = {
  'Product'             : app,
  'End of support date' : '2022-01-16'
};

var report = report_items_str(report_items:report_items, ordered_fields:ordered_fields);
   
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
