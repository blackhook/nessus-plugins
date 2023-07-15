#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148445);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_name(english:"Cisco Small Business RV Series Router Unsupported Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is no longer supported.");

  script_set_attribute(attribute:"description", value:
"The Cisco Small Business RV series router is no longer supported.

Note that only models RV110W, RV130, RV130W, and RV215W are detected
at this time.

Lack of support implies that no security patches for the product will
be released by the vendor.  As a result, it is likely to contain
security vulnerabilities.");

  # https://www.cisco.com/c/en/us/products/routers/small-business-rv-series-routers/eos-eol-notice-listing.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3bfb55f");
  # https://www.cisco.com/c/en/us/products/collateral/routers/small-business-rv-series-routers/eos-eol-notice-c51-742771.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b6eada4");
  # https://www.cisco.com/c/en/us/support/routers/small-business-rv-series-routers/series.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca8134c5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Cisco Small Business RV series router that is currently supported.");
  
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:small_business_rv_router_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:small_business_rv_router");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Model");

  exit(0);
}

# Model example: RV130W Wireless-N VPN Firewall
model = get_kb_item('Cisco/Small_Business_Router/Model');
if (empty_or_null(model)) audit(AUDIT_HOST_NOT, 'Cisco Small Business RV series router');

device = 'Cisco Small Business ' + model;

version = get_kb_item('Cisco/Small_Business_Router/Version');

# Grab just the simplified model (e.g. RV130W)
model_split = split(model, sep:' ', keep:FALSE);
model_key = model_split[0];

eos_dates = {
  'RV110W' : '2020-12-01',
  'RV130'  : '2020-12-01',
  'RV130W' : '2020-12-01',
  'RV215W' : '2020-12-01'
};

eos_date = eos_dates[model_key];

if (empty_or_null(eos_date))
  exit(0, strcat('The Cisco Small Business ', model, ' may still be supported. Please see note in the plugin description.'));

register_unsupported_product(
  product_name : device,
  version      : version,
  cpe_base     : 'cisco:small_business_rv_router_firmware'
);

ordered_fields = [ 'Product', 'End of support date' ];
report_items = {
  'Product'             : device,
  'End of support date' : eos_date
};

report = report_items_str(report_items:report_items, ordered_fields:ordered_fields);
   
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
